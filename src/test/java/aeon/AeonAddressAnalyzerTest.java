package aeon;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.After;
import org.junit.Test;

import generic.jar.ResourceFile;
import ghidra.GhidraTestApplicationLayout;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.plugin.core.analysis.ConstantPropagationAnalyzer;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.GModule;
import ghidra.framework.options.Options;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;
import utility.application.ApplicationLayout;
import utility.module.ModuleUtilities;

/**
 * AeonAddressAnalyzer on hand-built programs. The instruction bytes are the vendor
 * aeon-elf-as encodings of the assembly beside them; instructions are big-endian in
 * every AEON language, so the same bytes serve all three.
 */
public class AeonAddressAnalyzerTest extends AbstractGhidraHeadlessIntegrationTest {

	private static final String LE = "AEON:LE:32:R2";
	private static final String BE = "AEON:BE:32:R2";
	private static final String HARVARD = "AEON:LE:32:R2-harvard";

	/** Code is placed here; the block spans 0x20000..0x2ffff. */
	private static final String CODE = "0x20000";

	private static final byte[] JR_R9 = bytes(0x85, 0x29);

	private ProgramBuilder builder;
	private Program program;

	/**
	 * The test layout only finds modules inside the Ghidra install, so the AEON languages
	 * would be missing. Add this repo as a module, from the ghidra.external.modules property
	 * the build sets, as Ghidra's non-test layout already does.
	 */
	@Override
	protected ApplicationLayout createApplicationLayout() throws IOException {
		return new GhidraTestApplicationLayout(new File(getTestDirectoryPath())) {
			@Override
			protected Map<String, GModule> findGhidraModules() throws IOException {
				var modules = new HashMap<>(super.findGhidraModules());
				var external = System.getProperty("ghidra.external.modules", "");
				for (var path : external.split(File.pathSeparator)) {
					var dir = new ResourceFile(path);
					if (!path.isBlank() && ModuleUtilities.isModuleDirectory(dir)) {
						modules.putAll(ModuleUtilities.findModules(applicationRootDirs, List.of(dir)));
					}
				}
				return modules;
			}
		};
	}

	@After
	public void tearDown() {
		if (builder != null) {
			builder.dispose();
		}
	}

	// The stock propagator references an address returned in r3, and a load or store through
	// one, but not the completed address itself. The positive cases complete it in r11 and up,
	// so only AEON can account for the reference.

	@Test
	public void movhiAddiGetsADataReference() throws Exception {
		build(LE,
			0x95, 0x62,             // 0x20000 b.movhi r11,0x2
			0x1d, 0x6b, 0x40);      // 0x20002 b.addi  r11,r11,0x40
		analyze();
		assertDataRef("0x20002", "0x20040");
	}

	/** The control for the positive cases: the stock propagator alone leaves this out. */
	@Test
	public void stockPropagationAloneMissesTheAddress() throws Exception {
		build(LE,
			0x95, 0x62,             // 0x20000 b.movhi r11,0x2
			0x1d, 0x6b, 0x40);      // 0x20002 b.addi  r11,r11,0x40
		analyze(new ConstantPropagationAnalyzer());
		assertNoDataRef("0x20002");
	}

	/** AEON replaces the stock analyzer for this processor, so it must keep what stock does. */
	@Test
	public void returnedAddressKeepsItsStockReference() throws Exception {
		build(LE,
			0x94, 0x62,             // 0x20000 b.movhi r3,0x2
			0x1c, 0x63, 0x40);      // 0x20002 b.addi  r3,r3,0x40
		analyze();
		assertDataRef("0x20002", "0x20040");
	}

	/** The common firmware shape: a struct base. Stock references the load, AEON the base. */
	@Test
	public void loadBaseGetsADataReferenceBesideTheLoads() throws Exception {
		build(LE,
			0x94, 0xe2,             // 0x20000 b.movhi r7,0x2
			0x1c, 0xe7, 0x40,       // 0x20002 b.addi  r7,r7,0x40
			0x0c, 0xc7, 0x26);      // 0x20005 b.lwz   r6,0x24(r7)
		analyze();
		assertDataRef("0x20002", "0x20040");
		Reference[] load = program.getReferenceManager().getReferencesFrom(addr("0x20005"));
		assertEquals(Arrays.toString(load), 1, load.length);
		assertEquals(addr("0x20064"), load[0].getToAddress());
	}

	@Test
	public void movhiOriGetsADataReference() throws Exception {
		build(LE,
			0x95, 0x82,             // 0x20000 b.movhi r12,0x2
			0x51, 0x8c, 0x80);      // 0x20002 b.ori   r12,r12,0x80
		analyze();
		assertDataRef("0x20002", "0x20080");
	}

	@Test
	public void negativeAddiBorrowsFromTheHighHalf() throws Exception {
		build(LE,
			0x95, 0xa3,             // 0x20000 b.movhi r13,0x3
			0x9d, 0xb0);            // 0x20002 b.addi  r13,r13,-0x10
		analyze();
		assertDataRef("0x20002", "0x2fff0");
	}

	@Test
	public void valueCompletedFromR0IsNotAnAddress() throws Exception {
		build(LE,
			0x1e, 0x00, 0xf0);      // 0x20000 b.addi r16,r0,-0x10   (0xfffffff0)
		builder.createMemory("high", "0xffffff00", 0x100);
		analyze();
		assertNoDataRef("0x20000");
	}

	@Test
	public void valueBelow64KiBIsNotAnAddress() throws Exception {
		build(LE,
			0x95, 0xc0,             // 0x20000 b.movhi r14,0x0
			0xfd, 0xce, 0x70, 0x00);// 0x20002 b.addi  r14,r14,0x7000
		builder.createMemory("low", "0x7000", 0x100);
		analyze();
		assertNoDataRef("0x20002");
	}

	@Test
	public void valueOutsideMemoryIsNotAnAddress() throws Exception {
		build(LE,
			0x95, 0xe5,             // 0x20000 b.movhi r15,0x5
			0x1d, 0xef, 0x10);      // 0x20002 b.addi  r15,r15,0x10   (0x50010, unmapped)
		analyze();
		assertNoDataRef("0x20002");
	}

	@Test
	public void existingReferenceIsNotDuplicated() throws Exception {
		build(LE,
			0x95, 0x62,             // 0x20000 b.movhi r11,0x2
			0x1d, 0x6b, 0x40);      // 0x20002 b.addi  r11,r11,0x40
		tx(program, () -> program.getReferenceManager().addMemoryReference(addr("0x20002"),
			addr("0x20100"), RefType.DATA, SourceType.USER_DEFINED, 0));
		analyze();
		Reference[] refs = program.getReferenceManager().getReferencesFrom(addr("0x20002"), 0);
		assertEquals(Arrays.toString(refs), 1, refs.length);
		assertEquals(addr("0x20100"), refs[0].getToAddress());
	}

	@Test
	public void bigEndianDataLanguageMarksTheSameAddress() throws Exception {
		build(BE,
			0x95, 0x62,             // 0x20000 b.movhi r11,0x2
			0x1d, 0x6b, 0x40);      // 0x20002 b.addi  r11,r11,0x40
		analyze();
		assertDataRef("0x20002", "0x20040");
	}

	@Test
	public void harvardReferenceLandsInTheDataSpace() throws Exception {
		build(HARVARD,
			0x95, 0x62,             // 0x20000 b.movhi r11,0x2
			0x1d, 0x6b, 0x40);      // 0x20002 b.addi  r11,r11,0x40
		analyze();
		Address to = program.getAddressFactory().getAddressSpace("data").getAddress(0x20040);
		Reference ref = dataRef("0x20002");
		assertNotNull("no DATA reference on the addi", ref);
		assertEquals(to, ref.getToAddress());
	}

	/**
	 * A one-function program: the given code at CODE, then b.jr r9. The Harvard language
	 * also gets data memory at the same addresses, as its pspec maps data_ram.
	 * <p>
	 * Disassembly goes through the bare Disassembler, not ProgramBuilder's: that one runs
	 * auto-analysis, AEON's analyzer included, so every reference would exist before the
	 * test's own analyzer ran and no test could tell one analyzer from another.
	 */

	/** SPR 17 is SR: writes through mtspr must update the same bits consumed by flags. */
	@Test
	public void mtsprAndMfsprKeepStatusRegisterFlagsCoherent() throws Exception {
		for (String language : List.of(BE, LE, HARVARD)) {
			ProgramBuilder b = new ProgramBuilder("aeon-sr-spr", language, this);
			try {
				b.createMemory("ram", CODE, 0x1000);
				// b.mtspri r3,17 ; b.mfspri r4,17
				b.setBytes(CODE, bytes(
					0xc0, 0x60, 0x02, 0x25,
					0xc0, 0x80, 0x02, 0x27));
				Program p = b.getProgram();
				EmulatorHelper emu = new EmulatorHelper(p);
				try {
					emu.writeRegister("sr", 0);
					emu.writeRegister("r3", 0x600);
					emu.writeRegister("pc", 0x20000);
					assertTrue("mtspr failed for " + language, emu.step(TaskMonitor.DUMMY));
					assertTrue("mfspr failed for " + language, emu.step(TaskMonitor.DUMMY));
					assertEquals("SR value for " + language, 0x600,
						emu.readRegister("sr").longValue() & 0xffffffffL);
					assertEquals("SR[9] is F for " + language, 1,
						(emu.readRegister("sr").longValue() >>> 9) & 1L);
					assertEquals("SR[10] is CY for " + language, 1,
						(emu.readRegister("sr").longValue() >>> 10) & 1L);
					assertEquals("mfspr result for " + language, 0x600,
						emu.readRegister("r4").longValue() & 0xffffffffL);
				}
				finally {
					emu.dispose();
				}
			}
			finally {
				b.dispose();
			}
		}
	}

	/** RFE must restore both the saved exception PC and the complete saved SR. */
	@Test
	public void rfeRestoresSavedPcAndStatusRegister() throws Exception {
		for (String language : List.of(BE, LE, HARVARD)) {
			ProgramBuilder b = new ProgramBuilder("aeon-rfe", language, this);
			try {
				b.createMemory("ram", CODE, 0x1000);
				b.createMemory("spr", "spr:0", 0x200);
				// bt.rfe (instruction encoding is big-endian in every AEON language).
				b.setBytes(CODE, bytes(0x84, 0x00));
				int savedPc = 0x20100;
				int savedSr = 0x00000600;
				boolean little = !language.equals(BE);
				b.setBytes("spr:0x80", wordBytes(savedPc, little));   // EPCR0
				b.setBytes("spr:0x100", wordBytes(savedSr, little)); // ESR0
				Program p = b.getProgram();
				EmulatorHelper emu = new EmulatorHelper(p);
				try {
					emu.writeRegister("sr", 0);
					emu.writeRegister("pc", 0x20000);
					assertTrue("rfe failed for " + language, emu.step(TaskMonitor.DUMMY));
					assertEquals("restored PC for " + language, savedPc,
						emu.getExecutionAddress().getOffset());
					assertEquals("restored SR for " + language, savedSr,
						emu.readRegister("sr").longValue() & 0xffffffffL);
					assertEquals("restored F for " + language, 1,
						(emu.readRegister("sr").longValue() >>> 9) & 1L);
					assertEquals("restored CY for " + language, 1,
						(emu.readRegister("sr").longValue() >>> 10) & 1L);
				}
				finally {
					emu.dispose();
				}
			}
			finally {
				b.dispose();
			}
		}
	}

	private static byte[] wordBytes(int value, boolean little) {
		if (little) {
			return new byte[] {
				(byte) value, (byte) (value >>> 8),
				(byte) (value >>> 16), (byte) (value >>> 24)
			};
		}
		return new byte[] {
			(byte) (value >>> 24), (byte) (value >>> 16),
			(byte) (value >>> 8), (byte) value
		};
	}


	/**
	 * Scalar single-precision AEON FPU operations must be native FLOAT_* P-code,
	 * not opaque userops. Vectors are IEEE-754 bit patterns supplied directly in
	 * GPRs so the expected results are independent of host-language float formatting.
	 */
	@Test
	public void singlePrecisionFpuArithmeticConversionsAndComparisons() throws Exception {
		for (String language : List.of(BE, LE, HARVARD)) {
			ProgramBuilder b = new ProgramBuilder("aeon-fpu32", language, this);
			try {
				b.createMemory("ram", CODE, 0x1000);
				b.setBytes(CODE, bytes(
					0x74, 0xc3, 0x20, // addsf r6,r3,r4: 1.5 + 2.25 = 3.75
					0x74, 0xe4, 0x19, // subsf r7,r4,r3: 2.25 - 1.5 = 0.75
					0x75, 0x03, 0x24, // mulsf r8,r3,r4: 1.5 * 2.25 = 3.375
					0x75, 0x44, 0x1e, // divsf r10,r4,r3: 2.25 / 1.5 = 1.5
					0x75, 0x85, 0x02, // itof.s r12,r5: signed 42 -> 42.0f
					0x75, 0xa6, 0x03, // ftoi.s r13,r6: 3.75f -> 3
					0x78, 0x03, 0x18, // sfeqsf r3,r3
					0x78, 0x03, 0x21, // sflesf r3,r4
					0x78, 0x03, 0x24, // sfnesf r3,r4
					0x78, 0x04, 0x1d, // sfgtsf r4,r3
					0x78, 0x03, 0x25  // sfgtsf r3,r4 (false; must clear F)
				));
				EmulatorHelper emu = new EmulatorHelper(b.getProgram());
				try {
					emu.writeRegister("sr", 0);
					emu.writeRegister("r3", 0x3fc00000L); // 1.5f
					emu.writeRegister("r4", 0x40100000L); // 2.25f
					emu.writeRegister("r5", 42);
					emu.writeRegister("pc", 0x20000);
					for (int i = 0; i < 6; i++) {
						assertTrue("FPU instruction " + i + " failed for " + language,
							emu.step(TaskMonitor.DUMMY));
					}
					assertEquals("add 1.5 + 2.25 for " + language, 0x40700000L,
						emu.readRegister("r6").longValue() & 0xffffffffL);
					assertEquals("subtract 2.25 - 1.5 for " + language, 0x3f400000L,
						emu.readRegister("r7").longValue() & 0xffffffffL);
					assertEquals("multiply 1.5 * 2.25 for " + language, 0x40580000L,
						emu.readRegister("r8").longValue() & 0xffffffffL);
					assertEquals("divide 2.25 / 1.5 for " + language, 0x3fc00000L,
						emu.readRegister("r10").longValue() & 0xffffffffL);
					assertEquals("int to float 42 for " + language, 0x42280000L,
						emu.readRegister("r12").longValue() & 0xffffffffL);
					assertEquals("float to int truncates 3.75 for " + language, 3,
						emu.readRegister("r13").longValue() & 0xffffffffL);

					long[] expectedFlags = {1, 1, 1, 1, 0};
					for (int i = 0; i < expectedFlags.length; i++) {
						assertTrue("FPU compare " + i + " failed for " + language,
							emu.step(TaskMonitor.DUMMY));
						long flag = (emu.readRegister("sr").longValue() >>> 9) & 1L;
						assertEquals("FPU compare flag " + i + " for " + language,
							expectedFlags[i], flag);
					}
				}
				finally {
					emu.dispose();
				}
			}
			finally {
				b.dispose();
			}
		}
	}

	private void build(String language, int... code) throws Exception {
		builder = new ProgramBuilder("aeon", language, this);
		builder.createMemory("ram", CODE, 0x10000);
		if (language.equals(HARVARD)) {
			builder.createMemory("data", "data:" + CODE, 0x10000);
		}
		byte[] body = bytes(code);
		byte[] all = Arrays.copyOf(body, body.length + JR_R9.length);
		System.arraycopy(JR_R9, 0, all, body.length, JR_R9.length);
		builder.setBytes(CODE, all);
		program = builder.getProgram();
		Address entry = addr(CODE);
		tx(program, () -> {
			AddressSetView body2 = Disassembler.getDisassembler(program, TaskMonitor.DUMMY, null)
					.disassemble(entry, null);
			program.getFunctionManager()
					.createFunction("f", entry, body2, SourceType.USER_DEFINED);
		});
		assertEquals("references before analysis", 0,
			program.getReferenceManager().getReferenceCountFrom(entry.add(2)));
	}

	private void analyze() throws Exception {
		analyze(new AeonAddressAnalyzer());
	}

	/**
	 * Runs an analyzer the way auto-analysis does. canAnalyze matters: it is where the stock
	 * propagator sets its options for the program (speculative references off for a 32-bit
	 * space, among others), so skipping it would hide what AEON adds. Whether the stock
	 * analyzer claims the processor depends on whether an AeonAddressAnalyzer has been
	 * constructed yet in this JVM, so only AEON's answer is checked; the control test runs
	 * the stock one either way.
	 */
	private void analyze(ConstantPropagationAnalyzer analyzer) throws Exception {
		boolean claims = analyzer.canAnalyze(program);
		if (analyzer instanceof AeonAddressAnalyzer) {
			assertTrue("AEON does not claim the program's processor", claims);
		}
		var log = new MessageLog();
		tx(program, () -> {
			Options options = program.getOptions(Program.ANALYSIS_PROPERTIES)
					.getOptions(analyzer.getName());
			analyzer.registerOptions(options, program);
			analyzer.optionsChanged(options, program);
			analyzer.added(program, program.getMemory().getLoadedAndInitializedAddressSet(),
				TaskMonitor.DUMMY, log);
		});
	}

	private Reference dataRef(String from) {
		return Arrays.stream(program.getReferenceManager().getReferencesFrom(addr(from), 0))
				.filter(r -> r.getReferenceType() == RefType.DATA)
				.findFirst()
				.orElse(null);
	}

	private void assertDataRef(String from, String to) {
		Reference ref = dataRef(from);
		assertNotNull("no DATA reference at " + from, ref);
		assertEquals(addr(to), ref.getToAddress());
	}

	private void assertNoDataRef(String from) {
		assertNull("unexpected DATA reference at " + from, dataRef(from));
	}

	private Address addr(String address) {
		return builder.addr(address);
	}
}
