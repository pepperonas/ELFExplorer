#!/usr/bin/env python3
"""
Erweiterter Analyzer für .so-Dateien, besonders für Android/ARM-Bibliotheken
Benötigt: pip install pyelftools capstone
"""

import sys
import os
import re
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.dynamic import DynamicSection
from elftools.elf.relocation import RelocationSection
from elftools.elf.descriptions import describe_reloc_type
import struct

try:
    from capstone import *
    # Capstone 6 benennt ARM64 in AARCH64 um
    if 'CS_ARCH_ARM64' not in globals() and 'CS_ARCH_AARCH64' in globals():
        CS_ARCH_ARM64 = CS_ARCH_AARCH64
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    print("Hinweis: Capstone nicht installiert. Für Disassembly bitte installieren: pip install capstone")


def print_section_header(title):
    """Gibt eine formatierte Überschrift aus"""
    print("\n" + "=" * 80)
    print(f" {title} ".center(80, '='))
    print("=" * 80 + "\n")


def analyze_elf_header(elf):
    """Analysiert den ELF-Header"""
    print_section_header("ELF Header-Informationen")

    header = elf.header
    print(f"Magic:                    {' '.join([f'{b:02x}' for b in header['e_ident']['EI_MAG']])}")
    print(f"Klasse:                   {header['e_ident']['EI_CLASS']}")
    print(f"Daten:                    {header['e_ident']['EI_DATA']}")
    print(f"Version:                  {header['e_ident']['EI_VERSION']}")
    print(f"OS/ABI:                   {header['e_ident']['EI_OSABI']}")
    print(f"ABI Version:              {header['e_ident']['EI_ABIVERSION']}")
    print(f"Typ:                      {header['e_type']}")
    print(f"Maschine:                 {header['e_machine']}")
    print(f"Version:                  {header['e_version']}")
    print(f"Entry point:              0x{header['e_entry']:x}" if isinstance(header['e_entry'],
                                                                             int) else f"Entry point:              {header['e_entry']}")
    print(f"Program Header Offset:    0x{header['e_phoff']:x}" if isinstance(header['e_phoff'],
                                                                             int) else f"Program Header Offset:    {header['e_phoff']}")
    print(f"Section Header Offset:    0x{header['e_shoff']:x}" if isinstance(header['e_shoff'],
                                                                             int) else f"Section Header Offset:    {header['e_shoff']}")
    print(f"Flags:                    0x{header['e_flags']:x}" if isinstance(header['e_flags'],
                                                                             int) else f"Flags:                    {header['e_flags']}")
    print(f"Header Size:              {header['e_ehsize']} (Bytes)")
    print(f"Program Header Size:      {header['e_phentsize']} (Bytes)")
    print(f"Program Header Count:     {header['e_phnum']}")
    print(f"Section Header Size:      {header['e_shentsize']} (Bytes)")
    print(f"Section Header Count:     {header['e_shnum']}")
    print(f"String Table Index:       {header['e_shstrndx']}")


def analyze_sections(elf):
    """Analysiert die Abschnitte der ELF-Datei"""
    print_section_header("Abschnittsinformationen")

    # Abschnittstabelle ausgeben
    print(
        f"{'Nr':<5} {'Name':<20} {'Typ':<15} {'Adresse':<10} {'Offset':<10} {'Größe':<10} {'EntSize':<10} {'Flags':<7}")
    print("-" * 90)

    for i, section in enumerate(elf.iter_sections()):
        print(f"{i:<5} {section.name:<20} {section['sh_type']:<15} "
              f"{section['sh_addr']:#010x} {section['sh_offset']:#010x} "
              f"{section['sh_size']:#010x} {section['sh_entsize']:#010x} {section['sh_flags']:#07x}")


def analyze_dynamic_entries(elf):
    """Analysiert die dynamischen Abhängigkeiten"""
    print_section_header("Dynamische Abhängigkeiten")

    for section in elf.iter_sections():
        if isinstance(section, DynamicSection):
            print(f"Dynamische Einträge in Abschnitt {section.name}:")
            print(f"{'Tag':<20} {'Wert':<20} {'Name'}")
            print("-" * 70)

            for tag in section.iter_tags():
                if tag.entry.d_tag == 'DT_NEEDED':
                    print(f"{'NEEDED':<20} {tag.entry.d_val:<20} {tag.needed}")
                elif tag.entry.d_tag in ['DT_RPATH', 'DT_RUNPATH']:
                    print(f"{tag.entry.d_tag[3:]:<20} {tag.entry.d_val:<20} {tag.runpath}")
                elif tag.entry.d_tag == 'DT_SONAME':
                    print(f"{'SONAME':<20} {tag.entry.d_val:<20} {tag.soname}")
                else:
                    print(f"{tag.entry.d_tag[3:]:<20} {tag.entry.d_val:#x}")


def analyze_symbols(elf):
    """Analysiert die Symboltabelle der ELF-Datei"""
    print_section_header("Symboltabelle")

    jni_symbols = []
    other_symbols = []

    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue

        print(f"Symbole in {section.name}:")
        print(f"{'Nr':<5} {'Wert':<10} {'Größe':<10} {'Typ':<15} {'Bind':<10} {'Vis':<10} {'NDX':<5} {'Name'}")
        print("-" * 100)

        for i, symbol in enumerate(section.iter_symbols()):
            if not symbol.name:
                continue

            # JNI-Symbol-Muster identifizieren
            if symbol.name.startswith('Java_'):
                jni_symbols.append(symbol)
            else:
                other_symbols.append(symbol)

            print(f"{i:<5} {symbol['st_value']:#010x} {symbol['st_size']:<10} "
                  f"{symbol['st_info']['type']:<15} {symbol['st_info']['bind']:<10} "
                  f"{symbol['st_other']['visibility']:<10} {symbol['st_shndx']:<5} {symbol.name}")

    return jni_symbols, other_symbols


def _jni_unescape(part):
    """Löst die JNI-Escapes in einem Namensteil auf (_1 '_', _2 ';', _3 '[', _0xxxx Unicode)."""
    out = []
    i = 0
    while i < len(part):
        c = part[i]
        if c == '_' and i + 1 < len(part):
            nxt = part[i + 1]
            if nxt == '1':
                out.append('_')
                i += 2
                continue
            if nxt == '2':
                out.append(';')
                i += 2
                continue
            if nxt == '3':
                out.append('[')
                i += 2
                continue
            if nxt == '0' and i + 6 <= len(part) and re.fullmatch(r'[0-9a-fA-F]{4}', part[i + 2:i + 6]):
                out.append(chr(int(part[i + 2:i + 6], 16)))
                i += 6
                continue
        if c == '_':
            out.append('/')
        else:
            out.append(c)
        i += 1
    return ''.join(out)


def parse_jni_symbol(name):
    """
    Zerlegt einen JNI-Symbolnamen nach der JNI-Spezifikation.

    Java_<klasse>_<methode>[__<signatur>] mit '_' als Paket-/Klassen-Trenner und
    den Escapes _1 ('_'), _2 (';'), _3 ('['), _0xxxx (Unicode).

    Returns:
        (klasse, methode, signatur) mit Punkt-Notation für die Klasse und der
        Argument-Signatur (oder None), bzw. None wenn kein JNI-Symbol.
    """
    if not name.startswith('Java_'):
        return None
    body = name[len('Java_'):]

    # Überladene Methoden: "__" trennt die Argument-Signatur ab. Ein Escape
    # wie "_1" kann nie direkt auf ein "_" folgen, "__" ist also eindeutig.
    signature = None
    if '__' in body:
        body, signature = body.split('__', 1)
        signature = _jni_unescape(signature)

    decoded = _jni_unescape(body)
    if '/' not in decoded:
        return None
    class_path, method = decoded.rsplit('/', 1)
    if not class_path or not method:
        return None
    return class_path.replace('/', '.'), method, signature


def group_jni_methods(jni_symbols):
    """Gruppiert JNI-Symbole nach Klasse: {klasse: [{'method', 'signature', 'address', 'size'}]}"""
    class_methods = {}
    for symbol in jni_symbols:
        parsed = parse_jni_symbol(symbol.name)
        if parsed is None:
            continue
        class_name, method_name, signature = parsed
        class_methods.setdefault(class_name, []).append({
            'method': method_name,
            'signature': signature,
            'address': symbol['st_value'],
            'size': symbol['st_size']
        })
    return class_methods


def extract_jni_info(jni_symbols):
    """Extrahiert JNI-Klasseninformationen aus Symbolnamen"""
    print_section_header("JNI-Klassenstruktur")

    class_methods = group_jni_methods(jni_symbols)

    # Ausgabe der Klassenstruktur im hierarchischen Format
    for class_name, methods in class_methods.items():
        print(f"Klasse: {class_name}")
        for method in methods:
            sig = f"({method['signature']})" if method['signature'] is not None else ""
            print(f"  └─ {method['method']}{sig}: 0x{method['address']:x} (Größe: {method['size']} Bytes)")

    return class_methods


def find_strings(data, min_length=4):
    """
    Findet alle Folgen druckbarer ASCII-Zeichen (32-126) mit mindestens
    min_length Zeichen, wie `strings`. Auch eine Zeichenkette ganz am
    Dateiende wird erfasst.
    """
    if min_length < 1:
        raise ValueError("min_length muss mindestens 1 sein")
    pattern = re.compile(rb'[\x20-\x7e]{%d,}' % min_length)
    return [m.group().decode('ascii') for m in pattern.finditer(data)]


def categorize_strings(strings_found):
    """Sortiert Zeichenketten in die Kategorien java, android, path, function, other."""
    categories = {'java': [], 'android': [], 'path': [], 'function': [], 'other': []}
    for s in strings_found:
        lower = s.lower()
        if "java" in lower or "jni" in lower:
            categories['java'].append(s)
        elif "android" in lower:
            categories['android'].append(s)
        elif "/" in s:
            categories['path'].append(s)
        elif "(" in s and ")" in s:  # Mögliche Funktionssignaturen
            categories['function'].append(s)
        else:
            categories['other'].append(s)
    return categories


def extract_strings(filepath, min_length=4):
    """Extrahiert alle lesbaren Zeichenketten aus der Datei"""
    print_section_header("Interessante Zeichenketten")

    with open(filepath, 'rb') as f:
        content = f.read()

    categories = categorize_strings(find_strings(content, min_length))
    java_strings = categories['java']
    android_strings = categories['android']
    path_strings = categories['path']
    function_strings = categories['function']

    # Spezifische Strings nach Kategorie ausgeben
    if java_strings:
        print("Java/JNI-bezogene Strings:")
        for s in java_strings:
            print(f"  {s}")

    if android_strings:
        print("\nAndroid-bezogene Strings:")
        for s in android_strings:
            print(f"  {s}")

    if path_strings:
        print("\nPfade und Dateien:")
        for s in path_strings:
            print(f"  {s}")

    if function_strings:
        print("\nMögliche Funktionen und Methoden:")
        for s in function_strings:
            print(f"  {s}")


def disassemble_section(elf, section_name='.text', max_instructions=50):
    """Disassembliert einen bestimmten Abschnitt der ELF-Datei"""
    if not CAPSTONE_AVAILABLE:
        print("Capstone-Bibliothek nicht verfügbar. Disassembly wird übersprungen.")
        return

    print_section_header(f"Disassembly von {section_name}")

    # Relevante Architektur bestimmen
    arch = elf.header.e_machine
    if arch == 'EM_ARM':
        arch_mode = CS_ARCH_ARM
        mode = CS_MODE_ARM
    elif arch == 'EM_386':
        arch_mode = CS_ARCH_X86
        mode = CS_MODE_32
    elif arch == 'EM_X86_64':
        arch_mode = CS_ARCH_X86
        mode = CS_MODE_64
    elif arch == 'EM_AARCH64':
        arch_mode = CS_ARCH_ARM64
        mode = CS_MODE_ARM
    else:
        print(f"Nicht unterstützte Architektur: {arch}")
        return

    # Capstone-Disassembler initialisieren
    md = Cs(arch_mode, mode)
    md.detail = True

    # Abschnitt finden
    section = None
    for s in elf.iter_sections():
        if s.name == section_name:
            section = s
            break

    if section is None:
        print(f"Abschnitt {section_name} nicht gefunden.")
        return

    # Disassemblieren
    code = section.data()
    base_address = section['sh_addr']

    print(f"Disassembliere ersten {max_instructions} Instruktionen aus {section_name}...")
    print(f"{'Adresse':<10} {'Bytes':<20} {'Instruktion'}")
    print("-" * 80)

    count = 0
    for i in md.disasm(code, base_address):
        bytes_str = ' '.join([f"{b:02x}" for b in i.bytes])
        print(f"0x{i.address:08x}: {bytes_str:<20} {i.mnemonic} {i.op_str}")
        count += 1
        if count >= max_instructions:
            print(f"\n... (Limit von {max_instructions} Instruktionen erreicht)")
            break


def analyze_so(filepath):
    """Hauptfunktion zur vollständigen Analyse der .so-Datei"""
    if not os.path.exists(filepath):
        print(f"Fehler: Datei {filepath} nicht gefunden")
        return 1

    print(f"\n\nAnalysiere SO-Datei: {filepath}\n")

    try:
        with open(filepath, 'rb') as f:
            elf = ELFFile(f)

            # Header-Informationen
            analyze_elf_header(elf)

            # Abschnitte
            analyze_sections(elf)

            # Dynamische Abhängigkeiten
            analyze_dynamic_entries(elf)

            # Symboltabelle
            jni_symbols, other_symbols = analyze_symbols(elf)

            # JNI-Informationen extrahieren
            extract_jni_info(jni_symbols)

            # Strings extrahieren
            extract_strings(filepath)

            # Disassembly (nur wenn Capstone verfügbar ist)
            if CAPSTONE_AVAILABLE:
                disassemble_section(elf)

            return 0

    except Exception as e:
        print(f"Fehler bei der Analyse: {e}")
        import traceback
        traceback.print_exc()
        return 1


def main(argv=None):
    argv = sys.argv if argv is None else argv
    if len(argv) != 2:
        print(f"Nutzung: {argv[0]} <pfad_zur_so_datei>")
        return 1
    return analyze_so(argv[1])


if __name__ == "__main__":
    sys.exit(main())