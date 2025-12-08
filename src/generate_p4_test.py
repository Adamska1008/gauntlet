import argparse
import logging
import os
import sys
import itertools
import signal
from pathlib import Path

import z3
import p4z3.util as util

log = logging.getLogger(__name__)

FILE_DIR = Path(__file__).parent.resolve()
ROOT_DIR = FILE_DIR.parent
P4Z3_BIN = ROOT_DIR.joinpath("modules/p4c/build/p4toz3")
OUT_DIR = ROOT_DIR.joinpath("validated")
P4C_DIR = ROOT_DIR.joinpath("modules/p4c")

# v1model constants - hardcoded
INVALID_VAR = "invalid"
HEADER_VAR = "h"
PIPE_NAME = "ig"
INGRESS_VAR = "ig"

from lambdai import AI

class P4SemanticsExtractor:
    """Extract z3 semantics from p4 program (v1model only)"""

    def __init__(self, out_dir):
        self.out_dir = out_dir
        self.logger = logging.getLogger(__name__)

    def extract_semantics(self, p4_file: Path):
        """Extract z3 semantics from p4 program"""
        py_file = self._convert_to_python(p4_file)
        package = self._import_python_module(py_file)
        return package.get_pipes()

    def _convert_to_python(self, p4_file):
        """Convert P4 file to Python using p4toz3 compiler"""
        py_file = self.out_dir.joinpath(p4_file.with_suffix(".py").name)

        cmd = f"{P4Z3_BIN} {p4_file} --output {py_file}"
        self.logger.info("Converting p4 to z3 python with command %s", cmd)
        result = util.exec_process(cmd)

        if result.returncode != util.EXIT_SUCCESS:
            self.logger.error("Failed to translate P4 to Python.")
            raise RuntimeError(f"P4 to Python translation failed for {p4_file}")

        return py_file

    def _import_python_module(self, py_file):
        """Load Python module and get Z3 formulation"""
        from get_semantics import get_py_module, get_z3_asts

        p4py_module = get_py_module(py_file)
        if p4py_module is None:
            raise RuntimeError(f"Could not import Python module from {py_file}")

        package, result = get_z3_asts(p4py_module, py_file)
        if result != util.EXIT_SUCCESS:
            raise RuntimeError(f"Failed to generate Z3 ASTs from {py_file}")

        return package

class STFTestRunner:
    """Handles running STF tests on P4 programs"""

    def __init__(self, out_dir, p4_input):
        self.out_dir = out_dir
        self.p4_input = p4_input
        self.logger = logging.getLogger(__name__)

    def run_bmv2_test(self):
        """Run BMv2 test on P4 program"""
        cmd = f"python3 {P4C_DIR}/backends/bmv2/run-bmv2-test.py {P4C_DIR} -v -bd {P4C_DIR}/build {self.out_dir}/{self.p4_input.name}"
        test_proc = util.start_process(cmd, cwd=self.out_dir)

        def signal_handler(sig, frame):
            self.logger.warning("run_bmv2_test: Caught Interrupt, exiting...")
            os.kill(test_proc.pid, signal.SIGINT)
            sys.exit(1)
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        stdout, stderr = test_proc.communicate()
        return test_proc, stdout, stderr

    def run_stf_test(self, stf_str):
        """Run STF test with provided test string"""
        self.logger.info("Running stf test on file %s", self.p4_input)

        stf_file_name = self.out_dir.joinpath(f"{self.p4_input.stem}.stf")
        with open(stf_file_name, 'w+') as stf_file:
            stf_file.write(stf_str)

        result, stdout, stderr = self.run_bmv2_test()

        if result.returncode != util.EXIT_SUCCESS:
            self.logger.error("Failed to validate %s with a stf test:")
            self.logger.error("stdout: %s", stdout.decode("utf-8"))
            self.logger.error("stderr: %s", stderr.decode("utf-8"))
            return util.EXIT_FAILURE
        else:
            self.logger.info("Validation of %s with an stf test succeeded.", self.p4_input.name)
            return util.EXIT_SUCCESS

    
def get_stf_str(flat_input, flat_output, dont_care_map):
    """Generate STF string from input and output"""
    log.info("Generating stf string...")

    # Convert values to hex
    def to_hex(values):
        with AI:
            formatted_bits = AI.execute(
                """
                For all values of z3 data type {values}, handle it one by one.
                For z3.BoolRef, add 1 or 0 depending on whether it's true or not.
                For z3.BitVecRef, convert to binary using the as_long method.

                After getting a list of 0s and 1s, concatenate them and format as space-separated bytes: "00 01 10 11...".
                Each byte should be 2 hex characters.
                """, values=values,
            )
        return formatted_bits

    dont_care_vals = set()
    for val in flat_output:
        if isinstance(val, (z3.BitVecRef, z3.BoolRef)):
            for var in z3.z3util.get_vars(val):
                str_val = str(var)
                if str_val not in (INGRESS_VAR, INVALID_VAR):
                    dont_care_vals.add(str_val)

    # Generate STF output string using AI
    with AI:
        stf_str: str = AI.execute(
            """
            Generate STF test string from flat_input {flat_input}, flat_output {flat_output}, and dont_care_map {dont_care_map}:

            1. Convert flat_input to hex string using the {to_hex} function approach
            2. Convert flat_output to hex list using the <to_hex> function approach
            3. Process output list with dont_care_map:
               - For each marker at index i in dont_care_map:
                 * If marker == "x": remove bytes at positions i*4 and i*4+2 from output list
                 * If marker == "*": keep the bytes (no change)
            4. Join remaining output list to create output_str
            5. Create STF string:
               - packet 0 <input_hex>
               - expect 0 <output_hex> (only if output_str is not empty)

            Return the complete STF string.
            """, flat_input=flat_input, flat_output=flat_output, dont_care_map=dont_care_map, to_hex=to_hex
        )
    return stf_str

def get_branch_conditions(z3_formula):
    """Extract branch conditions from Z3 formula"""
    conditions = set()
    if isinstance(z3_formula, z3.BoolRef):
        if z3_formula.decl().kind() not in [z3.Z3_OP_NOT, z3.Z3_OP_AND, z3.Z3_OP_OR, z3.Z3_OP_XOR,
                                             z3.Z3_OP_IMPLIES, z3.Z3_OP_IFF, z3.Z3_OP_ITE]:
            conditions.add(z3_formula)
    for child in z3_formula.children():
        conditions |= get_branch_conditions(child)
    return conditions

def compute_permutations(permut_conds):
    """Compute permutations of conditions"""
    log.info("Computing permutations...")
    return [[f(var) for var, f in zip(permut_conds, x)]
            for x in itertools.product([z3.Not, lambda x: x], repeat=len(permut_conds))]

def analyze_z3_formula(pipes):
    """Analyze Z3 formula and return main formula, packet range, and conditions"""
    main_formula, p4_state, _ = pipes[PIPE_NAME]
    pkt_range = None

    # Find HEADER_VAR
    for member_name, member_type in p4_state.members:
        if member_name == HEADER_VAR:
            pkt_range = slice(0, len(member_type.flat_names))
            break

    if not pkt_range:
        log.error("No valid input formula found! Variable '%s' not found.", HEADER_VAR)
        return None, None, []

    main_formula = z3.simplify(main_formula)

    # Get branch conditions
    conditions = set()
    for child in main_formula.children()[pkt_range]:
        conditions |= get_branch_conditions(child)

    return main_formula, pkt_range, conditions

def dissect_conds(conditions):
    """Dissect conditions for v1model"""
    controllable_conds: list
    avoid_conds: list
    undefined_conds: list

    with AI:
        controllable_conds, avoid_conds, undefined_conds = AI.execute(
            """
            Analyze Z3 conditions {conditions} and categorize them for P4 test generation.

            Task: For each condition in {conditions}, extract and categorize its variables:

            1. Extract all variables from each condition using z3.z3util.get_vars()
            2. Simplify each condition with z3.simplify()

            Variable Analysis for each condition:
            - has_member: variable name contains "{INGRESS_VAR}"
            - has_table_key: variable name contains "table_key"
            - has_table_action: variable name contains "action"
            - has_undefined_var: variable is neither above AND:
              * If variable name contains "_valid": add the variable itself to undefined_conds
              * If variable is z3.BitVecRef: add (variable == 0) to undefined_conds
              * If variable is z3.BoolRef: add z3.Not(variable) to undefined_conds

            Condition Categorization:
            - controllable_conds: has_member AND no (has_table_key OR has_table_action OR has_undefined_var)
            - avoid_conds: has_table_key OR has_table_action OR (has_undefined_var AND not (has_table_key OR has_table_action))
            - undefined_conds: collected from individual undefined variables as described above

            Return: controllable_conds list, avoid_conds list, undefined_conds list
            """, conditions=conditions, INGRESS_VAR=INGRESS_VAR
        )

    permut_conds = compute_permutations(controllable_conds)

    log.info(15 * "#")
    log.info("Undefined conditions:")
    for cond in undefined_conds:
        log.info(cond)
    log.info("Conditions to avoid:")
    for cond in avoid_conds:
        log.info(cond)
    log.info("Permissible permutations:")
    for cond in controllable_conds:
        log.info(cond)
    log.info(15 * "#")

    return permut_conds, avoid_conds, undefined_conds

def build_test(main_formula, cond_tuple, pkt_range):
    """Build test case from Z3 formulas"""
    permut_conds, avoid_conds, undefined_conds = cond_tuple

    s = z3.Solver()
    output_const = z3.Const("output", main_formula.sort())
    s.add(main_formula == output_const)

    s.add(z3.And(*undefined_conds))
    s.add(z3.Not(z3.Or(*avoid_conds)))

    t = z3.Then(
        z3.Tactic("propagate-values"),
        z3.Tactic("ctx-solver-simplify"),
        z3.Tactic("elim-and")
    )

    stf_str = ""
    for permut in permut_conds:
        s.push()
        s.add(permut)
        log.info("Checking for solution...")
        if s.check() == z3.sat:
            m = s.model()
            log.info("Found a solution!")

            g = z3.Goal()
            g.add(main_formula == output_const,
                  z3.And(*undefined_conds), z3.Not(z3.Or(*avoid_conds)), z3.And(*permut))

            constrained_output = t.apply(g)
            output_var = constrained_output[0][0].children()[0]

            # Get don't care map
            dont_care_vals = set()
            for val in z3.z3util.get_vars(output_var):
                str_val = str(val)
                if str_val not in (INGRESS_VAR, INVALID_VAR):
                    dont_care_vals.add(str_val)

            flat_input = m[z3.Const(INGRESS_VAR, output_const.sort())].children()[pkt_range]
            flat_output = m[output_const].children()[pkt_range]

            stf_str += get_stf_str(flat_input, flat_output, build_dont_care_map(flat_output, dont_care_vals))
            stf_str += "\n"
        else:
            log.warning("No valid input could be found!")
        s.pop()

    return stf_str

def build_dont_care_map(flat_output, dont_care_vals):
    """Build don't care map for output"""
    with AI:
        dont_care_map: list = AI.execute(
            """
            Given flat_output list {flat_output} of Z3 values and dont_care_vals set {dont_care_vals}, create a dont_care_map:

            1. For each var in flat_output:
               - If z3.BoolRef: width = 1, else if z3.BitVecRef: width = var.size()
               - If str(var) == INVALID_VAR: extend dont_care_bit_map with ["x"] * width
               - Elif any dont_care_val in str(var): extend with ["*"] * width
               - Else: extend with ["."] * width

            2. Group dont_care_bit_map into 8-bit chunks and create dont_care_map:
               - If chunk contains "x": append "x"
               - Elif chunk contains "*": append "*"
               - Else: append "."

            Return dont_care_map list.
            """, flat_output=flat_output, dont_care_vals=dont_care_vals
        )
    return dont_care_map

def perform_blackbox_test(out_dir, p4_input):
    """Perform complete blackbox test"""
    logger = logging.getLogger(__name__)
    util.check_dir(out_dir)
    util.copy_file(p4_input, out_dir)
    semantics_extractor = P4SemanticsExtractor(out_dir)
    test_runner = STFTestRunner(out_dir, p4_input)

    # Get program semantics
    try:
        pipes = semantics_extractor.extract_semantics(p4_input)
    except Exception as e:
        logger.error("Failed to extract P4 semantics: %s", str(e))
        return util.EXIT_FAILURE

    # Analyze main formula
    main_formula, pkt_range, conditions = analyze_z3_formula(pipes)
    if main_formula is None or not pkt_range:
        return util.EXIT_FAILURE

    # Process conditions
    cond_tuple = dissect_conds(conditions)

    # Build test
    stf_str = build_test(main_formula, cond_tuple, pkt_range)

    # Run test
    return test_runner.run_stf_test(stf_str)

def main():
    """Ultra-simplified main function - v1model + single file only"""
    parser = argparse.ArgumentParser(description="P4 Test Generator - v1model architecture only")
    parser.add_argument("-i", "--p4_input", dest="p4_input", required=True,
                        help="Input P4 file path")
    parser.add_argument("-o", "--out_dir", dest="out_dir", default=OUT_DIR,
                        help="Output directory (default: validated)")
    parser.add_argument("-r", "--randomize-input", dest="randomize_input",
                        action='store_true',
                        help="Randomize z3 input variables")
    parser.add_argument("-l", "--log_file", dest="log_file",
                        default="model.log",
                        help="Log file name")
    parser.add_argument("--log_level", dest="log_level",
                        default="INFO",
                        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"],
                        help="Log level")

    args = parser.parse_args()

    # Validate input file (single file only)
    p4_input = Path(args.p4_input)
    if not p4_input.exists():
        print(f"Error: Input file {p4_input} does not exist")
        sys.exit(1)

    # Setup output directory
    out_dir = Path(args.out_dir).joinpath(p4_input.stem)
    util.del_dir(out_dir)  # Clean start for single file

    # Setup logging
    logging.basicConfig(
        filename=Path(args.out_dir).joinpath(args.log_file),
        format="%(levelname)s:%(message)s",
        level=getattr(logging, args.log_level),
        filemode='w'
    )

    # Also log to console
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter("%(levelname)s:%(message)s"))
    logging.getLogger().addHandler(console_handler)

    # Randomize if requested
    if args.randomize_input:
        seed = int.from_bytes(os.getrandom(8), "big")
        z3.set_param("smt.phase_selection", 5,
                     "smt.random_seed", seed,
                     "smt.arith.random_initial_value", True,
                     "sat.phase", "random")

    # Run test generation (single file only)
    result = perform_blackbox_test(out_dir, p4_input)

    sys.exit(result)

if __name__ == '__main__':
    main()