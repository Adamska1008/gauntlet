import argparse
import os
import logging
from pathlib import Path
import sys

import z3

from get_semantics import get_z3_formulization, run_p4_to_py
from p4z3 import util

FILE_DIR = Path(__file__).parent.resolve()
ROOT_DIR = FILE_DIR.parent
OUT_DIR = ROOT_DIR / "validated"


from lambdai import AI

HEADER_VAR = "h"
CONNECTIVE_OPS = [z3.Z3_OP_NOT, z3.Z3_OP_AND, z3.Z3_OP_OR, z3.Z3_OP_XOR,
                  z3.Z3_OP_IMPLIES, z3.Z3_OP_IFF, z3.Z3_OP_ITE]

log = logging.getLogger(__name__)


def get_prog_semantics(p4_input: Path, out_dir: Path):
    """
    Get z3-representation of the p4_input
    """
    py_file = Path(f"{out_dir}/{p4_input.stem}.py")
    fail_dir = out_dir / "failed"

    # TODO: this is handlable with lambdai
    result = run_p4_to_py(p4_input, py_file)
    if result.returncode != util.EXIT_SUCCESS:
        log.error("Failed to translate P4 to Python.")
        util.check_dir(fail_dir)
        with open(f"{fail_dir}/error.txt", "w+") as err_file:
            err_file.write(result.stderr.decode("utf-8"))
        util.copy_file([p4_input, py_file], fail_dir)
        return None, result.returncode
    package, result = get_z3_formulization(py_file)
    pipe_val = package.get_pipes()
    if result != util.EXIT_SUCCESS:
        if fail_dir and result != util.EXIT_SKIPPED:
            util.check_dir(fail_dir)
            util.copy_file([p4_input, py_file], fail_dir)
        return pipe_val, result
    return pipe_val, util.EXIT_SUCCESS


def get_main_formula(**kwargs):
    """
    Get a full transformation from input to output with given p4 program。
    Mostly depends on get_semantics.py
    """
    pipes, result = get_prog_semantics(kwargs)
    if result != util.EXIT_SUCCESS:
        return result
    pipe_name = kwargs.get("pipe_name")
    main_formula, p4_state, _ = pipes[pipe_name]
    main_formula = z3.simplify(main_formula)

    with AI:
        pkt_range: slice | None = AI.execute(
            """
            The {members} are a list of tuple(member_name, member_type), 
            and the member_type has an attr of flat_names(a list).

            Your job is to find the tuple with name {HEADER_VAR}, return a 
            slice(0, len(member_type.flat_names)).

            If you failed to find it, return None.
            """,
            members=p4_state.members,
            HEADER_VAR=HEADER_VAR,
        )
        if isinstance(pkt_range, None):
            log.error(
                "No valid input formula found!"
                " Check if your variable names are correct."
            )
            log.error(
                'This program checks for the "%s" variable in the pipe call.',
                HEADER_VAR,
            )
            return None, None
    return main_formula, pkt_range


def get_branch_conditions(z3_formula: z3.DatatypeRef):
    with AI:
        conditions: set = AI.execute(
            """
            Recursively extract atomic boolean conditions from a Z3 expression tree {z3_formula}.

            Collect all z3.BoolRef instances that represent basic conditions
            (at the leaf level of the expression tree), excluding any expressions
            that are logical connectives: {CONNECTIVE_OPS}.

            """, z3_formula=z3_formula, CONNECTIVE_OPS=CONNECTIVE_OPS
        )
    return conditions


def perform_blackbox_test(**kwargs):
    out_dir = kwargs.get("out_dir")
    p4_input = kwargs.get("p4_input")
    if out_dir == OUT_DIR:
        out_dir = out_dir / p4_input.stem
        kwargs["out_dir"] = out_dir
    util.check_dir(out_dir)
    util.copy_file(p4_input, out_dir)

    main_formula, pkt_range = get_main_formula(**kwargs)
    if main_formula == None or not pkt_range:
        return util.EXIT_FAILURE

    conditions = set()
    # extracts all branch conditions related to "input expr"
    for child in main_formula.children()[pkt_range]:
        conditions |= get_branch_conditions(child)

    pass


def main(args):
    config = {}
    # Assume the program is always v1model struct
    config["arch"] = "v1model"
    config["pipe_name"] = "ig"
    config["ingress_var"] = "ig"

    p4_input = Path(args.p4_input)
    out_base_dir = Path(args.out_dir)
    if os.path.isfile(p4_input):
        p4_files = [p4_input]
    else:
        util.check_dir(out_base_dir)
        p4_files = list(p4_input.glob("**/*.p4"))
    for p4_file in p4_files:
        out_dir = out_base_dir.joinpath(p4_input.stem)
        util.del_dir(out_dir)
        config["out_dir"] = out_dir
        config["p4_input"] = p4_file
        result = perform_blackbox_test(**config)
    sys.exit(result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i",
        "--p4_input",
        dest="p4_input",
        default=None,
        type=lambda x: util.is_valid_file(parser, x),
        help="The main reference p4 file.",
    )
    parser.add_argument(
        "-a",
        "--arch",
        dest="arch",
        default="v1model",
        type=str,
        help="Specify the back end to test.",
    )
    parser.add_argument(
        "-o",
        "--out_dir",
        dest="out_dir",
        default=OUT_DIR,
        help="The output folder where all passes are dumped.",
    )
    parser.add_argument(
        "-l",
        "--log_file",
        dest="log_file",
        default="model.log",
        help="Specifies name of the log file.",
    )
    parser.add_argument(
        "-r",
        "--randomize-input",
        dest="randomize_input",
        action="store_true",
        help="Whether to randomize the z3 input variables.",
    )
    parser.add_argument(
        "-ll",
        "--log_level",
        dest="log_level",
        default="INFO",
        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"],
        help="The log level to choose.",
    )
    # Parse options and process argv
    arguments = parser.parse_args()
    # configure logging
    logging.basicConfig(
        filename=arguments.log_file,
        format="%(levelname)s:%(message)s",
        level=getattr(logging, arguments.log_level),
        filemode="w",
    )
    stderr_log = logging.StreamHandler()
    stderr_log.setFormatter(logging.Formatter("%(levelname)s:%(message)s"))
    logging.getLogger().addHandler(stderr_log)
    main(arguments)
