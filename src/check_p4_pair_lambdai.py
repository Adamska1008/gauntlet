import argparse
import logging
import z3
from pathlib import Path
from get_semantics import get_z3_formulization

from p4z3 import util

from lambdai import AI

log = logging.getLogger(__name__)


def check_equivalence(prog_before, prog_after):
    z3_prog_before: z3.DatatypeRef
    z3_prog_after: z3.DatatypeRef
    z3_prog_before, _, _ = prog_before
    z3_prog_after, _, _ = prog_after

    with AI:
        ret: bool = AI.execute(
            """
            For {z3_prog_before} and {z3_prog_after}, you should determine if they are equivalent.
            Use library z3-solver (z3) to solve the question.

            Strategy:
            After simplify each program, build a z3-solver with tatic "simplify" and "smt", use the solver 
            to solve the solve the inequality (<z3_prog_before> != <z3_prog_after>).

            If result is sat or unknown, it means fails, return false. Otherwise return true.
            """,
            z3_prog_before=z3_prog_before,
            z3_prog_after=z3_prog_after,
        )
    return util.EXIT_SUCCESS if ret else util.EXIT_FAILURE


def z3_check(prog_paths: list[str]):
    info = {}
    if len(prog_paths) < 2:
        log.error("Equivalence checks require at least two input programs!")
        return util.EXIT_FAILURE, info
    z3_progs = []
    for p4_prog in prog_paths:
        p4_path = Path(p4_prog)
        package, result = get_z3_formulization(p4_path)
        if result != util.EXIT_SUCCESS:
            log.error("get z3 formulization failed")
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
            ret = check_equivalence(pipe_pre, pipe_post)
            if ret != util.EXIT_SUCCESS:
                log.warning("The (%s, %s) are different!", p4_pre_path, p4_post_path)
                return ret
    return util.EXIT_SUCCESS


def main(args):
    result = z3_check(args.progs)
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
        "-u",
        "--allow_undefined",
        dest="allow_undef",
        action="store_true",
        help="Ignore changes in undefined behavior.",
    )
    parser.add_argument(
        "-l",
        "--log_file",
        dest="log_file",
        default="check.log",
        help="Specifies name of the log file.",
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
