package aeon;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
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
				int savedPc = 0x20100;
				int savedSr = 0x00000600;
				// Populate the exception registers through mtspr, then execute RFE.
				b.setBytes(CODE, concatenate(
					sprImmediate(true, 3, 32),  // EPCR0 = r3
					sprImmediate(true, 4, 64),  // ESR0 = r4
					bytes(0x84, 0x00)));         // bt.rfe
				Program p = b.getProgram();
				EmulatorHelper emu = new EmulatorHelper(p);
				try {
					emu.writeRegister("sr", 0);
					emu.writeRegister("r3", savedPc);
					emu.writeRegister("r4", savedSr);
					emu.writeRegister("pc", 0x20000);
					assertTrue("EPCR0 mtspr failed for " + language, emu.step(TaskMonitor.DUMMY));
					assertTrue("ESR0 mtspr failed for " + language, emu.step(TaskMonitor.DUMMY));
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


	/** The MStar SYS SPR banks are architectural registers shared by SPR access and RFE. */
	@Test
	public void exceptionSprBanksAreNamedArchitecturalState() throws Exception {
		for (String language : List.of(BE, LE, HARVARD)) {
			ProgramBuilder b = new ProgramBuilder("aeon-exception-sprs", language, this);
			try {
				b.createMemory("ram", CODE, 0x10000);
				b.createMemory("spr", "spr:0", 0x200);
				byte[][] instructions = new byte[192][];
				for (int i = 0; i < 48; i++) {
					int spr = 32 + i;
					instructions[i * 2] = sprImmediate(true, 3, spr);
					instructions[i * 2 + 1] = sprImmediate(false, 4, spr);
					instructions[96 + i * 2] = sprRegister(true, 3, 5, 0);
					instructions[96 + i * 2 + 1] = sprRegister(false, 3, 4, 0);
				}
				b.setBytes(CODE, concatenate(instructions));
				EmulatorHelper emu = new EmulatorHelper(b.getProgram());
				try {
					emu.writeRegister("pc", 0x20000);
					for (int i = 0; i < 48; i++) {
						long value = (0xA5000000L | (i * 0x10101L)) & 0xffffffffL;
						emu.writeRegister("r3", value);
						assertTrue("immediate mtspr index " + (32 + i) + " failed for " + language,
							emu.step(TaskMonitor.DUMMY));
						assertTrue("immediate mfspr index " + (32 + i) + " failed for " + language,
							emu.step(TaskMonitor.DUMMY));
						assertEquals("immediate SPR readback index " + (32 + i) + " for " + language,
							value, emu.readRegister("r4").longValue() & 0xffffffffL);
						String bankName = i < 16 ? "epcr" + i : (i < 32 ? "eear" + (i - 16) : "esr" + (i - 32));
						assertEquals("named SPR varnode " + bankName + " for " + language,
							value, emu.readRegister(bankName).longValue() & 0xffffffffL);
					}
					for (int i = 0; i < 48; i++) {
						long value = (0x5A000000L | (i * 0x10203L)) & 0xffffffffL;
						emu.writeRegister("r3", 32 + i);
						emu.writeRegister("r5", value);
						assertTrue("register mtspr index " + (32 + i) + " failed for " + language,
							emu.step(TaskMonitor.DUMMY));
						assertTrue("register mfspr index " + (32 + i) + " failed for " + language,
							emu.step(TaskMonitor.DUMMY));
						assertEquals("register SPR readback index " + (32 + i) + " for " + language,
							value, emu.readRegister("r4").longValue() & 0xffffffffL);
						String bankName = i < 16 ? "epcr" + i : (i < 32 ? "eear" + (i - 16) : "esr" + (i - 32));
						assertEquals("dynamic named SPR varnode " + bankName + " for " + language,
							value, emu.readRegister(bankName).longValue() & 0xffffffffL);
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

	/** MStar names the three saved MAC words in its AEON R2 SPR header and vector save/restore code. */
	@Test
	public void macAccumulatorSprsAreNamedArchitecturalState() throws Exception {
		for (String language : List.of(BE, LE, HARVARD)) {
			ProgramBuilder b = new ProgramBuilder("aeon-mac-sprs", language, this);
			try {
				b.createMemory("ram", CODE, 0x1000);
				b.createMemory("spr", "spr:0", 0xB000);
				int[] sprs = {0x2801, 0x2802, 0x2803, 0x2808};
				String[] names = {"maclo", "machi", "machi2", "mulhi"};
				long[] values = {0x11223344L, 0x55667788L, 0x99aabbccL, 0xdeadc0deL};
				byte[][] instructions = new byte[sprs.length * 2][];
				for (int i = 0; i < sprs.length; i++) {
					instructions[i * 2] = sprImmediate(true, 3, sprs[i]);
					instructions[i * 2 + 1] = sprImmediate(false, 4, sprs[i]);
				}
				b.setBytes(CODE, concatenate(instructions));
				EmulatorHelper emu = new EmulatorHelper(b.getProgram());
				try {
					emu.writeRegister("pc", 0x20000);
					for (int i = 0; i < sprs.length; i++) {
						emu.writeRegister("r3", values[i]);
						assertTrue("mtspr " + names[i] + " failed for " + language,
							emu.step(TaskMonitor.DUMMY));
						assertTrue("mfspr " + names[i] + " failed for " + language,
							emu.step(TaskMonitor.DUMMY));
						assertEquals("SPR readback " + names[i] + " for " + language,
							values[i], emu.readRegister("r4").longValue() & 0xffffffffL);
						assertEquals("named register " + names[i] + " for " + language,
							values[i], emu.readRegister(names[i]).longValue() & 0xffffffffL);
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

	/** AEON's full 32x32 product writes the low word to rD and the high word to SPR_MULHI. */
	@Test
	public void signedAndUnsignedMultiplyExposeHighWord() throws Exception {
		for (String language : List.of(BE, LE, HARVARD)) {
			ProgramBuilder b = new ProgramBuilder("aeon-mul-high", language, this);
			try {
				b.createMemory("ram", CODE, 0x1000);
				b.createMemory("spr", "spr:0", 0xB000);
				b.setBytes(CODE, concatenate(
					bnMultiply(6, 3, 4, 3),
					sprImmediate(false, 7, 0x2808),
					bnMultiply(8, 3, 4, 2),
					sprImmediate(false, 9, 0x2808)));
				EmulatorHelper emu = new EmulatorHelper(b.getProgram());
				try {
					emu.writeRegister("r3", 0xfffffffdL); // -3 as signed, 4294967293 unsigned
					emu.writeRegister("r4", 5);
					emu.writeRegister("pc", 0x20000);
					for (int i = 0; i < 4; i++) {
						assertTrue("multiply instruction " + i + " failed for " + language,
							emu.step(TaskMonitor.DUMMY));
					}
					assertEquals("signed product low word for " + language, 0xfffffff1L,
						emu.readRegister("r6").longValue() & 0xffffffffL);
					assertEquals("signed product high word for " + language, 0xffffffffL,
						emu.readRegister("r7").longValue() & 0xffffffffL);
					assertEquals("unsigned product low word for " + language, 0xfffffff1L,
						emu.readRegister("r8").longValue() & 0xffffffffL);
					assertEquals("unsigned product high word for " + language, 4,
						emu.readRegister("r9").longValue() & 0xffffffffL);
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


	/**
	 * ENTRI and RTNEI are paired frame instructions. F counts saved GPRs
	 * beginning at r9; V counts additional local stack words. Saved registers
	 * occupy old_sp-4, old_sp-8, ... and RTNEI restores those exact locations.
	 */
	@Test
	public void entriAndRtneiRoundTripRegisterFrameAcrossAllVariants() throws Exception {
		for (String language : List.of(BE, LE, HARVARD)) {
			ProgramBuilder b = new ProgramBuilder("aeon-frame", language, this);
			try {
				b.createMemory("ram", CODE, 0x10000);
				if (language.equals(HARVARD)) {
					b.createMemory("data", "data:" + CODE, 0x10000);
				}
				// Vendor encodings: bn.entri 2,2 ; bn.rtnei 2,2
				b.setBytes(CODE, bytes(0x5c, 0x80, 0x58, 0x5c, 0x80, 0x5c));
				EmulatorHelper emu = new EmulatorHelper(b.getProgram());
				try {
					emu.writeRegister("r1", 0x20800);
					emu.writeRegister("r9", 0x11223344L);
					emu.writeRegister("r10", 0x55667788L);
					emu.writeRegister("pc", 0x20000);

					assertTrue("ENTRI failed for " + language, emu.step(TaskMonitor.DUMMY));
					assertEquals("allocated frame size for " + language, 0x207f0,
						emu.readRegister("r1").longValue() & 0xffffffffL);
					// Corrupt live values; RTNEI must recover them from the saved frame.
					emu.writeRegister("r9", 0xaaaaaaaaL);
					emu.writeRegister("r10", 0xbbbbbbbbL);
					assertTrue("RTNEI failed for " + language, emu.step(TaskMonitor.DUMMY));
					assertEquals("restored r9 for " + language, 0x11223344L,
						emu.readRegister("r9").longValue() & 0xffffffffL);
					assertEquals("restored r10 for " + language, 0x55667788L,
						emu.readRegister("r10").longValue() & 0xffffffffL);
					assertEquals("released frame size for " + language, 0x20800,
						emu.readRegister("r1").longValue() & 0xffffffffL);
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

	@Test
	public void entriRtneiHandleLocalOnlyFrames() throws Exception {
		for (String language : List.of(BE, LE, HARVARD)) {
			ProgramBuilder b = new ProgramBuilder("aeon-frame-locals", language, this);
			try {
				b.createMemory("ram", CODE, 0x10000);
				if (language.equals(HARVARD)) {
					b.createMemory("data", "data:" + CODE, 0x10000);
				}
				// bn.entri 0,3 ; bn.rtnei 0,3
				b.setBytes(CODE, bytes(0x5c, 0x00, 0x78, 0x5c, 0x00, 0x7c));
				EmulatorHelper emu = new EmulatorHelper(b.getProgram());
				try {
					emu.writeRegister("r1", 0x20800);
					emu.writeRegister("r9", 0x12345678L);
					emu.writeRegister("r10", 0x87654321L);
					emu.writeRegister("pc", 0x20000);
					assertTrue("ENTRI local-only failed for " + language, emu.step(TaskMonitor.DUMMY));
					assertEquals(0x207f4, emu.readRegister("r1").longValue() & 0xffffffffL);
					assertTrue("RTNEI local-only failed for " + language, emu.step(TaskMonitor.DUMMY));
					assertEquals(0x20800, emu.readRegister("r1").longValue() & 0xffffffffL);
					assertEquals(0x12345678L, emu.readRegister("r9").longValue() & 0xffffffffL);
					assertEquals(0x87654321L, emu.readRegister("r10").longValue() & 0xffffffffL);
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

	private static byte[] sprRegister(boolean write, int sprRegister, int valueRegister, int offset) {
		int opcode = write ? 0xD : 0xF;
		int word = (0x30 << 26) | (valueRegister << 21) | (sprRegister << 16) |
			((offset & 0xfff) << 4) | opcode;
		return bytes((word >>> 24) & 0xff, (word >>> 16) & 0xff,
			(word >>> 8) & 0xff, word & 0xff);
	}

	/** Whole-register SIMD bitwise instructions use native 128-bit P-code. */
	@Test
	public void vectorLogicalOperationsUseFull128BitRegisters() throws Exception {
		BigInteger a = new BigInteger("fedcba98765432100123456789abcdef", 16);
		BigInteger b = new BigInteger("0ff00ff00ff00ff0fedcba9876543210", 16);
		BigInteger mask = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE);
		for (String language : List.of(BE, LE, HARVARD)) {
			ProgramBuilder pb = new ProgramBuilder("aeon-vector-logic", language, this);
			try {
				pb.createMemory("ram", CODE, 0x1000);
				pb.setBytes(CODE, concatenate(
					vectorLogical(3, 1, 2, 2),  // mv.and v3,v1,v2
					vectorLogical(4, 1, 2, 6),  // mv.or v4,v1,v2
					vectorLogical(5, 1, 2, 14)  // mv.xor v5,v1,v2
				));
				EmulatorHelper emu = new EmulatorHelper(pb.getProgram());
				try {
					emu.writeRegister("v1", a);
					emu.writeRegister("v2", b);
					emu.writeRegister("pc", 0x20000);
					for (int i = 0; i < 3; i++) {
						assertTrue("vector logical instruction " + i + " failed for " + language,
							emu.step(TaskMonitor.DUMMY));
					}
					assertEquals("128-bit vector AND for " + language, a.and(b), emu.readRegister("v3").and(mask));
					assertEquals("128-bit vector OR for " + language, a.or(b), emu.readRegister("v4").and(mask));
					assertEquals("128-bit vector XOR for " + language, a.xor(b), emu.readRegister("v5").and(mask));
				}
				finally {
					emu.dispose();
				}
			}
			finally {
				pb.dispose();
			}
		}
	}

	private static byte[] vectorLogical(int destination, int left, int right, int subOpcode) {
		int word = (0x2c << 26) | (destination << 21) | (left << 16) |
			(right << 11) | (subOpcode & 0x3f);
		return bytes((word >>> 24) & 0xff, (word >>> 16) & 0xff,
			(word >>> 8) & 0xff, word & 0xff);
	}

	private static byte[] sprImmediate(boolean write, int register, int spr) {
		int opcode = write ? 5 : 7;
		int word = (0x30 << 26) | (register << 21) | ((spr & 0xffff) << 5) | opcode;
		return bytes((word >>> 24) & 0xff, (word >>> 16) & 0xff,
			(word >>> 8) & 0xff, word & 0xff);
	}

	private static byte[] bnMultiply(int destination, int left, int right, int subOpcode) {
		int word = (0x10 << 18) | (destination << 13) | (left << 8) |
			(right << 3) | subOpcode;
		return bytes((word >>> 16) & 0xff, (word >>> 8) & 0xff, word & 0xff);
	}

	private static byte[] concatenate(byte[]... parts) {
		int length = Arrays.stream(parts).mapToInt(part -> part.length).sum();
		byte[] result = new byte[length];
		int offset = 0;
		for (byte[] part : parts) {
			System.arraycopy(part, 0, result, offset, part.length);
			offset += part.length;
		}
		return result;
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
