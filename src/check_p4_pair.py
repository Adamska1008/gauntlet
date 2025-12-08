import argparse
from pathlib import Path
import sys
import logging
import z3

from p4z3.contrib.tabulate import tabulate
from get_semantics import get_z3_formulization
import p4z3.util as util
from p4z3.state import P4ComplexType

sys.setrecursionlimit(15000)

from lambdai import AI

FILE_DIR = Path(__file__).parent.resolve()
log = logging.getLogger(__name__)


def print_validation_error(prog_before, prog_after, model):
    z3_prog_before, p4_state_before, _ = prog_before
    z3_prog_after, p4_state_after, _ = prog_after
    error_string = "Detected an equivalence violation!\n"
    error_string += "\nPROGRAM BEFORE\n"
    error_string += get_hdr_table(z3_prog_before, p4_state_before.members)
    error_string += "\n\nPROGRAM AFTER\n"
    error_string += get_hdr_table(z3_prog_after, p4_state_after.members)
    error_string += "\n\nPROPOSED INPUT BEGIN\n"
    for decl in model.decls():
        value = model[decl]
        if isinstance(value, z3.DatatypeRef):
            error_string += "HEADER %s =\n" % decl
            error_string += get_hdr_table(value, p4_state_before.members)
        else:
            error_string += "%s = %s" % (decl, value)
        error_string += "\n--\n"
    error_string += "PROPOSED INPUT END\n"
    log.error(error_string)


def get_hdr_table(z3_datatype, p4_z3_objs):
    z3_datatype = z3.simplify(z3_datatype)
    flat_members = []
    for name, p4z3_obj in p4_z3_objs:
        if isinstance(p4z3_obj, P4ComplexType):
            for sub_member in p4z3_obj.flat_names:
                flat_members.append(f"{name}.{sub_member.name}")
        else:
            flat_members.append(name)
    outputs = z3_datatype.children()
    zipped_list = zip(flat_members, outputs)
    table = tabulate(zipped_list, headers=["NAME", "OUTPUT"])
    return table


def check_equivalence(prog_before, prog_after):
    z3_prog_before, input_names_before, _ = prog_before
    z3_prog_after, input_names_after, _ = prog_after

    with AI:
        ret, solver = AI.execute(
            """
            Check if two Z3 formulas {z3_prog_before} and {z3_prog_after} are equivalent.

            Create a solver to check if simplify(before != after) is satisfiable.
            - z3.sat means formulas are different (found counterexample)
            - z3.unsat means formulas are equivalent (no counterexample)

            Return: (ret, solver) where ret is the solver.check() result and solver is the solver instance.
            """,
            z3_prog_before=z3_prog_before,
            z3_prog_after=z3_prog_after,
        )

    if ret == z3.sat:
        print_validation_error(prog_before, prog_after, solver.model())
        return util.EXIT_VIOLATION
    elif ret == z3.unknown:
        log.error("Solution unknown! There might be a problem...")
        return util.EXIT_VIOLATION
    else:
        return util.EXIT_SUCCESS


def z3_check(prog_paths):
    info = {}

    if len(prog_paths) < 2:
        log.error("Equivalence checks require at least two input programs!")
        return util.EXIT_FAILURE, info

    z3_progs = []
    for p4_prog in prog_paths:
        p4_path = Path(p4_prog)
        package, result = get_z3_formulization(p4_path)
        if result != util.EXIT_SUCCESS:
            return result, info
        pipes = package.get_pipes()
        z3_progs.append((p4_path, pipes))

    for idx in range(1, len(z3_progs)):
        p4_pre_path, pipes_pre = z3_progs[idx - 1]
        p4_post_path, pipes_post = z3_progs[idx]
        log.info(
            "\nComparing programs\n%s\n%s\n########",
            p4_pre_path.stem,
            p4_post_path.stem,
        )

        if len(pipes_pre) != len(pipes_post):
            log.warning("Pre and post model differ in size!")
            return util.EXIT_SKIPPED, info

        for pipe_name in pipes_pre:
            pipe_pre = pipes_pre[pipe_name]
            pipe_post = pipes_post[pipe_name]
            log.info("Checking z3 equivalence for pipe %s...", pipe_name)
            ret = check_equivalence(pipe_pre, pipe_post)
            if ret != util.EXIT_SUCCESS:
                info["prog_before"] = str(p4_pre_path)
                info["prog_after"] = str(p4_post_path)
                return ret, info

    log.info("Passed all checks!")
    return util.EXIT_SUCCESS, info


def main(args):
    result, _ = z3_check(args.progs)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--progs",
        "-p",
        dest="progs",
        type=str,
        nargs="+",
        required=True,
        help="The ordered list of programs to compare.",
    )
    parser.add_argument(
        "-ll",
        "--log_level",
        dest="log_level",
        default="INFO",
        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"],
        help="The log level to choose.",
    )

    arguments = parser.parse_args()

    # Configure logging to console only
    logging.basicConfig(
        format="%(levelname)s:%(message)s", level=getattr(logging, arguments.log_level)
    )

    sys.exit(main(arguments))
