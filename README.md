# PE Dagger Server

<br>
<div align=center>
  <img width="100" height="100" alt="image" src="https://github.com/user-attachments/assets/57b62bd7-2a8a-4b14-8862-b5f7e3bf8f77" />
</div>
<br><br>
<div align=center>

[![Contributors](https://img.shields.io/github/contributors/binsentry/pedagger?color=2ea44f&logo=github)](https://github.com/lyshark/pedagger/graphs/contributors)
[![Email Support](https://img.shields.io/badge/Contact-admin@lyshark.com-0099ff?logo=gmail)](mailto:admin@lyshark.com)
[![Release Download](https://img.shields.io/github/downloads/lyshark/pedagger/total?color=orange&logo=windows)](https://github.com/lyshark/pedagger/releases/tag/pedagger)

[![Python 3.x](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)](https://github.com/lyshark/pedagger)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64dbg-lightgrey?logo=windows)](https://github.com/lyshark/pedagger)
[![binsentry Version](https://img.shields.io/github/v/tag/lyshark/pedagger?label=Version&sort=semver&color=success)](https://github.com/lyshark/pedagger/releases)

[![GitHub Stars](https://img.shields.io/github/stars/lyshark/pedagger?style=social)](https://github.com/lyshark/pedagger/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/lyshark/pedagger?style=social)](https://github.com/lyshark/pedagger/fork)
[![License](https://img.shields.io/github/license/lyshark/pedagger)](https://github.com/lyshark/pedagger/blob/main/LICENSE)

</div>

A static parsing and rewriting service for executable programs, which only listens on a single port after startup and provides an interface to the outside world through HTTP+JSON. It can complete header parsing, import/export table analysis, disassembly, section rewriting, resource and relocation reconstruction, signature auditing, and other capabilities in a single request. It also supports multi session isolation and concurrent operation.

## Quick Start

Users may install the corresponding pedagger engine toolkit via pip:

```python
CMD> pip install PeDagger==1.0.0
CMD> pip show pedagger
Name: PeDagger
Version: 1.0.0
Summary:
Home-page: http://pedagger.lyshark.com
Author: lyshark
Author-email: me@lyshark.com
License: MIT Licence
```

Simply call the PEDagger library to achieve the ability to analyze specific PE files.

```python
from PeDagger import *

if __name__ == "__main__":
    # Initialize PEDagger client connection
    cli = PEDaggerClient(address="127.0.0.1", port=8947, api_key="45d3552b12b12cdf2c831344311cf81e")

    # Create client session pool
    resp = cli.session_create()

    # Open two sessions simultaneously
    s1 = cli.open_file("c://Win32_Debug.exe",session="session1")
    s2 = cli.open_file("c://x32_Debug.dll",session="session2")

    # View session list
    print(cli.session_list())

    # Call nt_head method for each session
    res_nt1 = cli.nt_head(session="session1")
    res_nt2 = cli.nt_head(session="session2")

    # Print results
    print(res_nt1)
    print(res_nt2)

    # Close sessions
    cli.session_close(session_id="session1")
    cli.session_close(session_id="session2")
```

Use PEdagger to perform static file disassembly tasks as shown below.

```python
from PeDagger import *

if __name__ == "__main__":
    # Initialize PEDagger client connection
    cli = PEDaggerClient(address="127.0.0.1", port=8947, api_key="45d3552b12b12cdf2c831344311cf81e")

    # Create client session pool
    resp = cli.session_create()

    # Open two sessions simultaneously
    s1 = cli.open_file("c://Win32_Debug.exe",session="session1")

    res_disasm = cli.disassemble_at("foa", "0x8A0", size=100, session="session1")
    print("Disassembly result:")
    print(res_disasm)

    # Close session
    cli.session_close(session_id="session1")
```
