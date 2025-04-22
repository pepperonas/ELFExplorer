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


def extract_jni_info(jni_symbols):
    """Extrahiert JNI-Klasseninformationen aus Symbolnamen"""
    print_section_header("JNI-Klassenstruktur")

    class_methods = {}

    for symbol in jni_symbols:
        name_parts = symbol.name.split('_')

        if len(name_parts) < 3:
            continue

        # Format: Java_package_class_method
        # Ignoriere den ersten Teil "Java"
        package_class_parts = name_parts[1:-1]  # Alles zwischen "Java" und Methodenname
        method_name = name_parts[-1]

        # Rekonstruiere den Klassennamen mit Punktnotation
        class_name = '.'.join(package_class_parts)

        if class_name not in class_methods:
            class_methods[class_name] = []

        class_methods[class_name].append({
            'method': method_name,
            'address': symbol['st_value'],
            'size': symbol['st_size']
        })

    # Ausgabe der Klassenstruktur im hierarchischen Format
    for class_name, methods in class_methods.items():
        print(f"Klasse: {class_name}")
        for method in methods:
            print(f"  └─ {method['method']}: 0x{method['address']:x} (Größe: {method['size']} Bytes)")


def extract_strings(filepath, min_length=4):
    """Extrahiert alle lesbaren Zeichenketten aus der Datei"""
    print_section_header("Interessante Zeichenketten")

    with open(filepath, 'rb') as f:
        content = f.read()

    strings_found = []
    current_string = b""

    for byte in content:
        if 32 <= byte <= 126:  # ASCII druckbare Zeichen
            current_string += bytes([byte])
        else:
            if len(current_string) >= min_length:
                strings_found.append(current_string.decode('ascii', errors='ignore'))
            current_string = b""

    # Nach Kategorien sortieren
    java_strings = []
    android_strings = []
    path_strings = []
    function_strings = []
    other_strings = []

    for s in strings_found:
        if "java" in s.lower() or "jni" in s.lower():
            java_strings.append(s)
        elif "android" in s.lower():
            android_strings.append(s)
        elif "/" in s:
            path_strings.append(s)
        elif "(" in s and ")" in s:  # Mögliche Funktionssignaturen
            function_strings.append(s)
        else:
            other_strings.append(s)

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


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Nutzung: {sys.argv[0]} <pfad_zur_so_datei>")
        sys.exit(1)

    so_path = sys.argv[1]
    sys.exit(analyze_so(so_path))