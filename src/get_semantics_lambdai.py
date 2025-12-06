import argparse
from pathlib import Path
import sys
import importlib
import logging
import z3

from p4z3.contrib.tabulate import tabulate
from p4z3.state import StaticContext, P4ComplexType, P4Extern
import p4z3.util as util
from p4z3.externs.core import core_externs

sys.setrecursionlimit(15000)

FILE_DIR = Path(__file__).parent.resolve()
P4Z3_BIN = FILE_DIR.joinpath("../modules/p4c/build/p4toz3")
OUT_DIR = FILE_DIR.joinpath("../validated")
log = logging.getLogger(__name__)


def get_z3_formulization(p4_file, out_dir=OUT_DIR):
    """Extract Z3 semantics from P4 file"""

    # Convert P4 to Python if needed
    if p4_file.suffix == ".p4":
        util.check_dir(out_dir)
        py_file = out_dir.joinpath(p4_file.with_suffix(".py").name)
        cmd = f"{P4Z3_BIN} {p4_file} --output {py_file}"
        result = util.exec_process(cmd)

        if result.returncode != util.EXIT_SUCCESS:
            log.error("Failed to translate P4 to Python.")
            return None, result.returncode
        p4_file = py_file

    # Import Python module
    try:
        ctrl_dir = p4_file.parent
        ctrl_name = p4_file.stem
        finder = importlib.machinery.PathFinder()
        module_specs = finder.find_spec(str(ctrl_name), [str(ctrl_dir)])
        module = module_specs.loader.load_module()
        p4py_module = getattr(module, "p4_program")
    except (ImportError, SyntaxError) as e:
        log.error("Could not import the requested module: %s", e)
        return None, util.EXIT_FAILURE

    # Generate Z3 ASTs
    log.info("Loading %s ASTs...", p4_file.name)
    try:
        prog_ctx = StaticContext()
        prog_ctx.add_extern_extensions(core_externs)
        p4_package = p4py_module(prog_ctx)
        if not p4_package:
            log.warning("No main module, nothing to evaluate!")
            return None, util.EXIT_SKIPPED
        return p4_package, util.EXIT_SUCCESS
    except Exception:
        log.exception("Failed to compile Python to Z3:\n")
        return None, util.EXIT_FAILURE


def get_flat_members(names):
    """Flatten member names for display"""
    flat_members = []
    for name, p4z3_obj in names:
        if isinstance(p4z3_obj, P4ComplexType):
            for sub_member in p4z3_obj.flat_names:
                flat_members.append(f"{name}.{sub_member.name}")
        else:
            flat_members.append(name)
    return flat_members


def reconstruct_input(pipe_name, p4_state, pipe_cls):
    """Reconstruct input state from P4 state"""
    if isinstance(pipe_cls, P4Extern):
        initial_state = z3.Const(f"{pipe_name}", pipe_cls.z3_type)
    else:
        prog_ctx = StaticContext()
        p4_state.initialize(prog_ctx)
        initial_state = p4_state.get_z3_repr(prog_ctx)
    return initial_state.children()


def print_z3_data(pipe_name, pipe_val):
    """Print Z3 data in tabular format"""
    z3_datatype, p4_state, pipe_cls = pipe_val
    z3_datatype = z3.simplify(z3_datatype)

    flat_members = get_flat_members(p4_state.members)
    inputs = reconstruct_input(pipe_name, p4_state, pipe_cls)
    outputs = z3_datatype.children()

    zipped_list = zip(flat_members, inputs, outputs)
    table = tabulate(zipped_list, headers=["NAME", "INPUT", "OUTPUT"])
    log.info("PIPE %s:\n%s\n", pipe_name, table)


def main(args):
    package, result = get_z3_formulization(Path(args.p4_input), Path(args.out_dir))

    if result == util.EXIT_SUCCESS:
        for pipe_name, pipe_val in package.get_pipes().items():
            print_z3_data(pipe_name, pipe_val)

    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i",
        "--p4_input",
        dest="p4_input",
        required=True,
        help="The main input p4 file.",
    )
    parser.add_argument(
        "-o",
        "--out_dir",
        dest="out_dir",
        default=str(OUT_DIR),
        help="Where intermediate output is stored.",
    )
    parser.add_argument(
        "-ll",
        "--log_level",
        dest="log_level",
        default="INFO",
        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"],
        help="The log level to choose.",
    )

    arguments = parser.parse_args()

    # Configure logging to console only
    logging.basicConfig(
        format="%(levelname)s:%(message)s",
        level=getattr(logging, arguments.log_level)
    )

    sys.exit(main(arguments))