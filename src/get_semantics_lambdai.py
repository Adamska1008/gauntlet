import argparse
from datetime import datetime
import logging
from pathlib import Path
import time

from p4z3.contrib.tabulate import tabulate
from p4z3 import util
from p4z3.state import StaticContext, P4ComplexType, P4Extern, P4State
from p4z3.externs.core import core_externs
import z3


from lambdai import AI

FILE_DIR = Path(__file__).parent.resolve()
P4Z3_BIN = FILE_DIR / "../modules/p4c/build/p4toz3"
OUT_DIR = FILE_DIR / "../validated"
log = logging.getLogger(__name__)


def run_p4_to_py(p4_file, py_file):
    cmd = f"{P4Z3_BIN} "
    cmd += f"{p4_file} "
    cmd += f"--output {py_file} "
    return util.exec_process(cmd)


def get_py_module(prog_path: Path):
    log.info("Getting py module from %s", prog_path)
    function_name = "p4_program"
    with AI:
        module = AI.execute(
            """
            Find the module in the program in {prog_path} and 
            extracts function {function_name} from the module.
            """,
            prog_path=prog_path,
            function_name=function_name,
        )
    return module


def get_z3_formulization(p4_file: Path, out_dir=OUT_DIR):
    if p4_file.suffix == ".p4":
        util.check_dir(out_dir)
        py_file = out_dir / p4_file.with_suffix(".py").name
        run_p4_to_py(p4_file, py_file)
        p4_file = py_file
    p4py_module = get_py_module(p4_file)
    prog_ctx = StaticContext()
    prog_ctx.add_extern_extensions(core_externs)
    p4_package = p4py_module(prog_ctx)
    return p4_package


# def print_z3_data(pipe_name, pipe_val):
#     z3_datatype: z3.DatatypeRef
#     p4_state: P4State
#     z3_datatype, p4_state, pipe_cls = pipe_val
#     with AI:
#         AI.execute(
#             """
#             Print info of
#             """
#         )


def get_flat_members(names):
    flat_members = []
    for name, p4z3_obj in names:
        if isinstance(p4z3_obj, P4ComplexType):
            for sub_member in p4z3_obj.flat_names:
                flat_members.append(f"{name}.{sub_member.name}")
        else:
            flat_members.append(name)
    return flat_members


def reconstruct_input(pipe_name, p4_state, pipe_cls):
    # these names are not quite accurate
    if isinstance(pipe_cls, P4Extern):
        initial_state = z3.Const(f"{pipe_name}", pipe_cls.z3_type)
    else:
        prog_ctx = StaticContext()
        p4_state.initialize(prog_ctx)
        initial_state = p4_state.get_z3_repr(prog_ctx)

    inital_inputs = initial_state.children()
    return inital_inputs


def handle_nested_ifs(pipe_name, flat_members, inputs, outputs):
    cond = outputs[0]
    then_outputs = outputs[1].children()
    else_outputs = outputs[2].children()
    if z3.z3util.is_app_of(outputs[1], z3.Z3_OP_ITE):
        handle_nested_ifs(pipe_name, flat_members, inputs, then_outputs)
    else:
        zipped_list = zip(flat_members, inputs, then_outputs)
        table = tabulate(zipped_list, headers=["NAME", "INPUT", "OUTPUT"])
        log.info('PIPE %s Condition:\n"%s"\n%s\n', pipe_name, cond, table)
        zipped_list = zip(flat_members, inputs, then_outputs)

    if z3.z3util.is_app_of(outputs[2], z3.Z3_OP_ITE):
        handle_nested_ifs(pipe_name, flat_members, inputs, else_outputs)
    else:
        zipped_list = zip(flat_members, inputs, else_outputs)
        table = tabulate(zipped_list, headers=["NAME", "INPUT", "OUTPUT"])
        log.info('PIPE %s Condition:\n"%s"\n%s\n', pipe_name, z3.Not(cond), table)
        zipped_list = zip(flat_members, inputs, else_outputs)


def print_z3_data(pipe_name, pipe_val):
    z3_datatype, p4_state, pipe_cls = pipe_val
    z3_datatype = z3.simplify(z3_datatype)
    flat_members = get_flat_members(p4_state.members)
    inputs = reconstruct_input(pipe_name, p4_state, pipe_cls)
    outputs = z3_datatype.children()
    if z3.z3util.is_app_of(z3_datatype, z3.Z3_OP_ITE):
        handle_nested_ifs(pipe_name, flat_members, inputs, outputs)
    else:
        zipped_list = zip(flat_members, inputs, outputs)
        table = tabulate(zipped_list, headers=["NAME", "INPUT", "OUTPUT"])
        log.info("PIPE %s:\n%s\n", pipe_name, table)
    # log.info("%-20s %-20s %-20s" % ("NAME", "INPUT", "OUTPUT"))
    # log.info("-" * 60)
    # w = max([max(len(str(x)) for x in col) for col in zipped_list])
    # zipped_list = zip(flat_members, inputs, outputs)
    # for name, input, output in zipped_list:
    #     row = f"{name: <{w}} {str(input): <{w}} {str(output): <{w}}"
    #     log.info(row)


def main(args):
    start_time = datetime.now()
    p4_input = Path(args.p4_input)
    out_dir = Path(args.out_dir)
    package = get_z3_formulization(p4_input, out_dir)
    done_time = datetime.now()
    elapsed = done_time - start_time
    time_str = time.strftime(
        "%H hours %M minutes %S seconds", time.gmtime(elapsed.total_seconds())
    )
    ms = elapsed.microseconds / 1000
    log.info("Retrieving semantics took %s %s milliseconds.", time_str, ms)
    for pipe_name, pipe_val in package.get_pipes().items():
        print_z3_data(pipe_name, pipe_val)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i",
        "--p4_input",
        dest="p4_input",
        default=None,
        type=lambda x: util.is_valid_file(parser, x),
        help="The main input p4 file. This can either be a P4"
        " program or the Python ToZ3 IR.",
    )
    parser.add_argument(
        "-o",
        "--out_dir",
        dest="out_dir",
        default=OUT_DIR,
        help="Where intermediate output is stored.",
    )
    parser.add_argument(
        "-l",
        "--log_file",
        dest="log_file",
        default="semantics.log",
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
