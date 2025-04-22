# ELFExplorer

ELFExplorer is a Python tool for detailed analysis of ELF (Executable and Linkable Format) files, particularly `.so`
files (Shared Libraries) commonly used in Android/ARM libraries. It provides features such as ELF header analysis,
section overview, symbol table inspection, dynamic dependencies, JNI structure extraction, string extraction, and
disassembly (if Capstone is installed). The tool is ideal for reverse engineering, security analysis, and debugging
native libraries.

## Features

- **ELF Header Analysis**: Displays metadata such as architecture, endianness, file type, and entry point.
- **Section Overview**: Lists all sections with their type, address, size, and flags.
- **Dynamic Dependencies**: Shows required libraries and other dynamic entries.
- **Symbol Table**: Lists symbols (functions, variables) with a focus on JNI symbols.
- **JNI Class Structure**: Extracts and organizes JNI methods and classes from symbol names.
- **String Extraction**: Extracts readable strings, categorized by Java/JNI, Android, paths, and functions.
- **Disassembly**: Disassembles the `.text` section for supported architectures (ARM, x86, x86_64, AArch64) if Capstone
  is available.

## Requirements

- **Python**: Version 3.6 or higher
- **Operating System**: Linux, macOS, or Windows
- **Dependencies**:
    - `pyelftools>=0.29`: For ELF file analysis
    - `capstone>=4.0.2`: For disassembly (optional)

## Installation

1. **Clone the repository or download the script**:

   ```bash
   git clone <repository-url>
   cd ELFExplorer
   ```

2. **Create a virtual environment** (recommended):

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

   The `requirements.txt` contains:

   ```
   pyelftools>=0.29
   capstone>=4.0.2
   ```

4. **Verify the installation**:

   ```bash
   pip list
   ```

   Ensure that `pyelftools` and `capstone` (if desired) are installed.

## Usage

Run the script with a `.so` file as an argument:

```bash
python3 elfexplorer.py <path_to_so_file>
```

Example:

```bash
python3 elfexplorer.py /path/to/libexample.so
```

### Output

The script outputs a detailed analysis to the console, including:

- ELF header information
- Section overview
- Dynamic dependencies
- Symbol table with JNI symbols
- JNI class structure
- Extracted strings (categorized)
- Disassembly of the `.text` section (if Capstone is installed)

### Note

If Capstone is not installed, disassembly will be skipped, and a notice will be displayed. Install Capstone with
`pip install capstone` to enable this feature.

## Supported Architectures

- **ARM** (`EM_ARM`, `EM_AARCH64`): Common in Android libraries
- **x86** (`EM_386`): 32-bit architectures
- **x86_64** (`EM_X86_64`): 64-bit architectures

Other architectures will trigger a warning that they are not supported.

## Limitations

- Disassembly requires the `capstone` library.
- Large `.so` files may result in longer analysis times.
- Some architectures or specific ELF formats may not be fully supported.

## Contributing

Contributions are welcome! If you find bugs or want to suggest new features:

1. Create an issue in the repository.
2. Submit a pull request with your changes.

---

*Built for reverse engineers, security analysts, and developers seeking deep insights into ELF files.*