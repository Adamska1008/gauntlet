from datetime import datetime
import json
import logging
import argparse
import os
from pathlib import Path
import sys
import time

import p4z3.util as util
import check_p4_pair as z3check

from lambdai import AI

log = logging.getLogger(__name__)


FILE_DIR = Path(__file__).parent.resolve()
P4C_BIN = FILE_DIR.joinpath("../modules/p4c/build/p4test")
P4Z3_BIN = FILE_DIR.joinpath("../modules/p4c/build/p4toz3")
PASS_DIR = FILE_DIR.joinpath("../validated")


PASSES = "--top4 "
PASSES += "FrontEnd,MidEnd,PassManager "

INFO = {
    "compiler": str(P4C_BIN),
    "exit_code": util.EXIT_SUCCESS,
    "prog_before": "",
    "prog_after": "",
    "p4z3_bin": str(P4Z3_BIN),
    "out_dir": str(PASS_DIR),
    "input_file": "",
    "allow_undef": False,
    "validation_bin": f"python3 {__file__}",
    "err_string": "",
}

def check_dir(directory: str):
    with AI:
        AI.execute("If {directory} not exists, create it.", directory=directory)


def run_p4_to_py(p4_file, py_file):
    cmd = f"{P4Z3_BIN} "
    cmd += f"{p4_file} "
    cmd += f"--output {py_file} "
    return util.exec_process(cmd)


def create_pass_files(p4c_bin, target_dir: Path, p4_file: Path):
    """
    Generate and filter P4 compiler intermediate pass files.

    This function executes the P4C compiler to dump intermediate representations,
    extracts pass names from verbose output, and removes redundant passes.

    Args:
        p4c_bin: Path to P4C compiler binary
        target_dir: Output directory for intermediate files
        p4_file: Input P4 source file path

    Returns:
        List of unique intermediate pass file paths in execution order
    """
    p4_cmd = f"{p4c_bin} {PASSES} --dump {target_dir} {p4_file}"
    with AI:
        log.debug("Running dumps with command %s ", p4_cmd)
        # Dumps intermediate files
        AI.execute(
            """
            Execute the command in a sub process:
            {p4_cmd}
            """,
            p4_cmd=p4_cmd,
        )
        verbose_cmd = f"{p4c_bin} -v {p4_file}"
        log.debug("Grabbing passes with command %s", verbose_cmd)
        passes: list[str] = AI.execute(
            """
            Execute command: {verbose_cmd}
            
            Parse the output to extract compiler pass names:
            1. Keep only lines containing "FrontEnd", "MidEnd", or "PassManager"
            2. Remove lines containing "Writing program to"

            Returns a list of the ouptut lines.
            """,
            verbose_cmd=verbose_cmd,
        )
        pass_files: list[Path] = AI.execute(
            """
            Transform each <pass_str> in {passes} to a Path, 
            that file_name is {file_stem}-<pass_str>.p4
            and it's in directory {target_dir}.
            """,
            passes=passes,
            file_stem=p4_file.stem,
            target_dir=target_dir,
        )
        pass_files: list[Path] = AI.execute(
            """
            Filter redundant intermediate files by comparing file contents:
            
            Input pass_files: {pass_files}
            
            For each adjacent pair of files in the list:
            1. Calculate SHA256 hash of both file contents
            2. If hashes are identical, remove the latter file (it's redundant)
            3. If hashes differ, keep both files (they represent actual program changes)
            
            Return the filtered list of unique files in execution order.
            """,
            pass_files,
        )
    return pass_files


def validate_translation(
    p4_file: Path, target_dir: Path, p4c_bin, allow_undef=False, dump_info=False
):
    info = INFO
    log.info("\n" + "-" * 70)
    log.info("Analysing %s", p4_file)

    start_time = datetime.now()
    check_dir(target_dir)
    passes = create_pass_files(p4c_bin, target_dir, p4_file)
    fail_dir = target_dir.joinpath("failed")

    p4_py_files = []
    # for each emitted pass, generate a python representation
    for p4_pass in passes:
        p4_path = Path(p4_pass).stem
        py_file = f"{target_dir}/{p4_path}.py"
        result = run_p4_to_py(p4_pass, py_file)
        if result.returncode != util.EXIT_SUCCESS:
            log.error("Failed to translate P4 to Python.")
            log.error("Compiler crashed!")
            util.check_dir(fail_dir)
            with open(f"{fail_dir}/error.txt", "w+") as err_file:
                err_file.write(result.stderr.decode("utf-8"))
            util.copy_file([p4_pass, py_file], fail_dir)
            return result.returncode
        p4_py_files.append(f"{target_dir}/{p4_path}")
    if len(p4_py_files) < 2:
        log.warning("P4 file did not generate enough passes!")
        return util.EXIT_SKIPPED
    # perform the actual comparison
    result, check_info = z3check.z3_check(p4_py_files, fail_dir, allow_undef)
    # merge the two info dicts
    info["exit_code"] = result
    info = {**info, **check_info}
    done_time = datetime.now()
    elapsed = done_time - start_time
    time_str = time.strftime(
        "%H hours %M minutes %S seconds", time.gmtime(elapsed.total_seconds())
    )
    ms = elapsed.microseconds / 1000
    log.info("Translation validation took %s %s milliseconds.", time_str, ms)
    if dump_info:
        json_name = target_dir.joinpath(f"{p4_file.stem}_info.json")
        log.info("Dumping configuration to %s.", json_name)
        with open(json_name, "w") as json_file:
            json.dump(info, json_file, indent=2, sort_keys=True)
    return result


def main(args):

    p4_input = Path(args.p4_input).resolve()
    pass_dir = Path(args.pass_dir)
    p4c_bin = args.p4c_bin
    allow_undef = args.allow_undef
    dunp_info = args.dunp_info
    # customize the main info with the new information
    INFO["compiler"] = str(p4c_bin)
    INFO["exit_code"] = util.EXIT_SUCCESS
    INFO["p4z3_bin"] = str(P4Z3_BIN)
    INFO["input_file"] = str(p4_input)
    INFO["allow_undef"] = allow_undef
    INFO["validation_bin"] = f"python3 {__file__}"

    log.info("\n" + "-" * 70)
    log.info("Analysing %s", p4_input)
    if os.path.isfile(p4_input):
        pass_dir = pass_dir.joinpath(p4_input.stem)
        INFO["out_dir"] = str(pass_dir)
        util.del_dir(pass_dir)
        result = validate_translation(
            p4_input, pass_dir, p4c_bin, allow_undef, dunp_info
        )
        sys.exit(result)
    elif os.path.isdir(p4_input):
        util.check_dir(pass_dir)
        for p4_file in list(p4_input.glob("**/*.p4")):
            output_dir = pass_dir.joinpath(p4_file.stem)
            util.del_dir(output_dir)
            INFO["out_dir"] = str(output_dir)
            validate_translation(p4_file, output_dir, p4c_bin, allow_undef)
        result = util.EXIT_SUCCESS
    else:
        log.error('Input file "%s" does not exist!', p4_input)
        result = util.EXIT_SUCCESS
    sys.exit(result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i",
        "--p4_input",
        dest="p4_input",
        default="p4c/testdata/p4_16_samples",
        required=True,
        help="A P4 file or path to a " "directory which contains P4 files.",
    )
    parser.add_argument(
        "-o",
        "--out_dir",
        dest="pass_dir",
        default=PASS_DIR,
        help="The output folder where all passes are dumped.",
    )
    parser.add_argument(
        "-p",
        "--p4c_bin",
        dest="p4c_bin",
        default=P4C_BIN,
        help="Specifies the p4c binary to compile a p4 file.",
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
        default="analysis.log",
        help="Specifies name of the log file.",
    )
    parser.add_argument(
        "-d",
        "--dump_info",
        dest="dunp_info",
        action="store_true",
        help="Dump an informative JSON file in" " the output directory.",
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
