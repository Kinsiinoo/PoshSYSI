# PoshSYSI

PowerShell System Information 0.1.0

This PowerShell script gives information about the following things on the specified machine:

- Bios
  - S/N *(mostly useful on laptops)*
  - Version
  - Etc.
- CPU
  - Socket
  - Model
  - Etc.
- Installed programs (x86 + x64)
  - Name
  - Version
- Monitor(s) *(mostly useful for non-integrated displays)*
  - Model
  - PCID
  - S/N
  - Etc.
- RAM *(mostly useful on laptops)*
  - Available
  - Manufacturer
  - P/N
  - S/N
- Storage ( C:\ )
  - Total/Free
- System
  - Model *(mostly useful on laptops)*
  - Name
  - User
- Windows
  - License status
  - Product name
  - Version
  - Etc.

## Screenshots

WIP

## Syntax

```PowerShell
Get-PoshSYSI [[-ComputerName] <string[]>]  [<CommonParameters>]
```

## Usage

For now, only on a local machine:

```PowerShell
Get-PoshSYSI
```

## Todo

- [X] More info :thinking:
- [X] Refactor code into a nice PS module :eyes:
  - [ ] Run on multiple computer
  - [ ] Modes (`Full`, `Normal`, `Minimal`)
  - [ ] Report (maybe `.csv` and/or `.xlsx` and/or `.html`)
- [ ] GUI version
  - [ ] Multilingual interface

## License

PoshSYSI is licensed under the MIT License.
