import io
import pytest
from elftools.elf.elffile import ELFFile

import elfexplorer as ee
from elf_builder import EM_X86_64, build_elf

SYMBOLS = [
    ("Java_com_example_MyClass_init", 0x1000, 6),
    ("Java_com_example_MyClass_native_1method", 0x1000, 6),
    ("Java_com_example_Foo_bar__ILjava_lang_String_2", 0x1004, 2),
    ("helper_function", 0x1002, 2),
]


class _Sym(dict):
    def __init__(self, name, value, size):
        super().__init__(st_value=value, st_size=size)
        self.name = name


# --- JNI demangling ----------------------------------------------------------

@pytest.mark.parametrize("name,expected", [
    ("Java_com_example_MyClass_init", ("com.example.MyClass", "init", None)),
    # underscores in names are escaped as _1 (used to become class ...native / method 1method)
    ("Java_com_example_MyClass_native_1method", ("com.example.MyClass", "native_method", None)),
    ("Java_com_my_1app_Main_run", ("com.my_app.Main", "run", None)),
    # overloaded: "__" + argument signature (_2 = ';', _3 = '[')
    ("Java_com_example_Foo_bar__ILjava_lang_String_2", ("com.example.Foo", "bar", "ILjava/lang/String;")),
    ("Java_a_B_m___3B", ("a.B", "m", "[B")),
    ("Java_a_B_m__", ("a.B", "m", "")),
    # _0xxxx = Unicode character
    ("Java_a_Gr_000fc_000dfe_x", ("a.Grüße", "x", None)),
    ("Java_Main_run", ("Main", "run", None)),           # default package
])
def test_parse_jni_symbol(name, expected):
    assert ee.parse_jni_symbol(name) == expected


@pytest.mark.parametrize("name", ["main", "Java_", "Java_onlyone", "JNI_OnLoad", "java_a_b"])
def test_non_jni_symbols(name):
    assert ee.parse_jni_symbol(name) is None


def test_group_jni_methods():
    grouped = ee.group_jni_methods([_Sym(n, v, s) for n, v, s in SYMBOLS[:3]] + [_Sym("Java_x", 0, 0)])
    assert list(grouped) == ["com.example.MyClass", "com.example.Foo"]
    assert [m["method"] for m in grouped["com.example.MyClass"]] == ["init", "native_method"]
    assert grouped["com.example.Foo"] == [
        {"method": "bar", "signature": "ILjava/lang/String;", "address": 0x1004, "size": 2}]


# --- strings -----------------------------------------------------------------

def test_find_strings_like_unix_strings():
    data = b"\x00abc\x00abcd\x01/system/lib\xff\x7fhello world\n12"
    assert ee.find_strings(data) == ["abcd", "/system/lib", "hello world"]
    assert ee.find_strings(data, min_length=3) == ["abc", "abcd", "/system/lib", "hello world"]


def test_find_strings_includes_string_at_end_of_file():
    # The trailing run used to be dropped because no terminator followed it.
    assert ee.find_strings(b"\x00\x00android.permission.CAMERA") == ["android.permission.CAMERA"]


def test_find_strings_edges():
    assert ee.find_strings(b"") == []
    assert ee.find_strings(b"abc") == []
    assert ee.find_strings(b" ~~~ ") == [" ~~~ "]          # 0x20 and 0x7e are printable
    with pytest.raises(ValueError):
        ee.find_strings(b"x", min_length=0)


def test_categorize_strings():
    cats = ee.categorize_strings([
        "Ljava/lang/String;", "JNI_OnLoad", "android/os/Build", "/system/lib/libc.so",
        "malloc(size_t)", "plain text", "ANDROID_ROOT",
    ])
    assert cats["java"] == ["Ljava/lang/String;", "JNI_OnLoad"]
    assert cats["android"] == ["android/os/Build", "ANDROID_ROOT"]   # android wins over path
    assert cats["path"] == ["/system/lib/libc.so"]
    assert cats["function"] == ["malloc(size_t)"]
    assert cats["other"] == ["plain text"]


# --- analysis of a generated ELF file -----------------------------------------

@pytest.fixture
def so_file(tmp_path):
    path = tmp_path / "libdemo.so"
    path.write_bytes(build_elf(SYMBOLS, needed=("liblog.so", "libc.so"),
                               extra_rodata=b"/data/local/tmp\0Java_trailing\0"))
    return path


def elf_of(path):
    return ELFFile(io.BytesIO(path.read_bytes()))


def test_builder_produces_parseable_elf(so_file):
    elf = elf_of(so_file)
    assert elf.header["e_machine"] == "EM_X86_64"
    assert elf.header["e_type"] == "ET_DYN"
    assert [s.name for s in elf.iter_sections()][1:] == [
        ".text", ".rodata", ".dynstr", ".dynamic", ".strtab", ".symtab", ".shstrtab"]


def test_header_output(so_file, capsys):
    ee.analyze_elf_header(elf_of(so_file))
    out = capsys.readouterr().out
    assert "Magic:                    7f 45 4c 46" in out
    assert "ELFCLASS64" in out and "EM_X86_64" in out
    assert "Entry point:              0x1000" in out


def test_sections_output(so_file, capsys):
    ee.analyze_sections(elf_of(so_file))
    out = capsys.readouterr().out
    assert ".symtab" in out and "SHT_DYNAMIC" in out
    assert "0x00001000" in out          # .text address


def test_dynamic_entries(so_file, capsys):
    ee.analyze_dynamic_entries(elf_of(so_file))
    out = capsys.readouterr().out
    assert "liblog.so" in out and "libc.so" in out
    assert "SONAME" in out and "libdemo.so" in out


def test_symbols_split_jni_from_others(so_file, capsys):
    jni, other = ee.analyze_symbols(elf_of(so_file))
    assert [s.name for s in jni] == [s[0] for s in SYMBOLS[:3]]
    assert [s.name for s in other] == ["helper_function"]
    assert "helper_function" in capsys.readouterr().out


def test_jni_output(so_file, capsys):
    jni, _ = ee.analyze_symbols(elf_of(so_file))
    capsys.readouterr()
    ee.extract_jni_info(jni)
    out = capsys.readouterr().out
    assert "Klasse: com.example.MyClass" in out
    assert "native_method: 0x1000" in out
    assert "bar(ILjava/lang/String;): 0x1004" in out


def test_strings_output(so_file, capsys):
    ee.extract_strings(str(so_file))
    out = capsys.readouterr().out
    assert "/data/local/tmp" in out
    assert "Java_trailing" in out


def test_disassembly_x86_64(so_file, capsys):
    pytest.importorskip("capstone")
    ee.disassemble_section(elf_of(so_file), max_instructions=10)
    out = capsys.readouterr().out
    assert "0x00001000: 55" in out and "push" in out
    assert "ret" in out


def test_disassembly_limit(so_file, capsys):
    pytest.importorskip("capstone")
    ee.disassemble_section(elf_of(so_file), max_instructions=2)
    out = capsys.readouterr().out
    lines = [l for l in out.splitlines() if l.startswith("0x0000")]
    assert len(lines) == 2                                   # exactly the limit
    assert "push" in lines[0] and "mov" in lines[1]
    assert "Limit von 2" in out


def test_disassembly_unsupported_arch(tmp_path, capsys):
    pytest.importorskip("capstone")
    path = tmp_path / "riscv.so"
    path.write_bytes(build_elf(SYMBOLS, machine=243))      # EM_RISCV
    ee.disassemble_section(elf_of(path))
    assert "Nicht unterstützte Architektur" in capsys.readouterr().out


def test_disassembly_missing_section(so_file, capsys):
    pytest.importorskip("capstone")
    ee.disassemble_section(elf_of(so_file), section_name=".nope")
    assert "nicht gefunden" in capsys.readouterr().out


def test_aarch64_constants_exist():
    pytest.importorskip("capstone")
    # The script uses CS_ARCH_ARM64 for EM_AARCH64; capstone 6 renamed it to
    # CS_ARCH_AARCH64, the import block maps it back.
    assert hasattr(ee, "CS_ARCH_ARM64")


def test_analyze_so_end_to_end(so_file, capsys):
    assert ee.analyze_so(str(so_file)) == 0
    out = capsys.readouterr().out
    assert "JNI-Klassenstruktur" in out and "com.example.Foo" in out


def test_analyze_so_errors(tmp_path, capsys):
    assert ee.analyze_so(str(tmp_path / "missing.so")) == 1
    junk = tmp_path / "junk.so"
    junk.write_bytes(b"not an elf file")
    assert ee.analyze_so(str(junk)) == 1


def test_main_usage(capsys):
    assert ee.main(["elfexplorer.py"]) == 1
    assert "Nutzung" in capsys.readouterr().out
