# -*- coding: utf-8 -*-
import json
import os
import socket
from urllib.parse import urlparse
from typing import List, Dict, Union, Optional, Callable, Any, Sequence
from functools import wraps

__all__ = [
    "check_server_available",
    "validate_hex_address",
    "parse_response",
    "DEFAULT_API_KEY",
    "ENV_API_KEY",
    "DEFAULT_PORT",
    "SUPPORTED_INTERFACES",
    "Config",
    "BaseHttpClient",
    "ServiceApi",
    "SessionApi",
    "HeaderApi",
    "AddressApi",
    "MemoryApi",
    "FieldApi",
    "SectionApi",
    "ImportApi",
    "ExportApi",
    "RelocApi",
    "DisasmApi",
    "EditApi",
    "AnalyzeApi",
    "SecurityApi",
    "HashApi",
    "CalcApi",
    "PEDaggerClient",
]

def check_server_available(func: Callable) -> Callable:
    """调用前先探测 TCP 端口；不可用则直接返回统一错误 JSON 字符串。"""
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if not self.config.is_server_available():
            return json.dumps({
                "status": "error",
                "message": "Server unavailable"
            }, ensure_ascii=False)
        return func(self, *args, **kwargs)
    return wrapper

def _normalize_numeric_text(value: Any) -> str:
    """移除地址/数值中的空白及转义空白标记，避免解析在中途被截断。"""
    text = str(value)
    normalized: List[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char.isspace():
            index += 1
            continue
        if char == "\\" and index + 1 < len(text) and text[index + 1] in "trnvf":
            index += 2
            continue
        normalized.append(char)
        index += 1
    return "".join(normalized)

def validate_hex_address(address: Union[int, str]) -> Optional[str]:
    """把 int / "0x..." / 十进制串规范化为服务端可接受的地址串，非法返回 None。"""
    if isinstance(address, int):
        return hex(address)
    addr_str = _normalize_numeric_text(address)
    if not addr_str:
        return None
    if addr_str.startswith(('0x', '0X')):
        try:
            int(addr_str, 16)
            return addr_str
        except ValueError:
            return None
    try:
        int(addr_str, 10)
        return addr_str
    except ValueError:
        return None

def parse_response(text: str) -> Optional[Dict]:
    """把 SDK 返回的 JSON 字符串解析为 dict；解析失败返回 None。"""
    if not text:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None

def _pack(*values: Any) -> List[str]:
    """把位置参数打包成服务端要求的字符串数组。

    None 表示“该位置缺省”，并从尾部裁剪；中间位置的 None 传空串，
    以满足服务端“按顺序取参”的解析方式。
    """
    out: List[str] = []
    for v in values:
        out.append("" if v is None else str(v))
    while out and out[-1] == "":
        out.pop()
    return out

def _exact(count: int, *values: Any) -> List[str]:
    """固定参数个数的打包：服务端声明 "requires N parameter(s)" 的接口必须传满 N 个，
    不能像 _pack 那样裁剪尾部空串，否则会被判为参数个数错误。"""
    out: List[str] = []
    for v in values[:count]:
        out.append("" if v is None else str(v))
    while len(out) < count:
        out.append("")
    return out

def _addr(value: Union[int, str], what: str = "address") -> str:
    """校验并规范化地址参数（VA / RVA / FOA 通用）。"""
    s = validate_hex_address(value)
    if s is None:
        raise ValueError("invalid %s: %r" % (what, value))
    return s

DEFAULT_API_KEY = "45d3552b12b12cdf2c831344311cf81e"
DEFAULT_PORT = 8947
ENV_API_KEY = "PEDAGGER_TOKEN"

def _default_api_key() -> str:
    """未显式传入 api_key 时的取值：环境变量 PEDAGGER_TOKEN，否则 DEFAULT_API_KEY。"""
    return os.environ.get(ENV_API_KEY, "") or DEFAULT_API_KEY

SUPPORTED_INTERFACES = (
    "Open", "FileBasicInfo", "DosHead", "NtHead", "Section", "OptionalDataDirectory",
    "ImportByDll", "ImportByName", "ImportByFunction", "ImportAll", "Export",
    "FixRelocPage", "FixReloc", "Resource", "VAToFOA", "RVAToFOA", "FOAToVA",
    "VAToRVA", "RVAToVA", "HexASCII", "SearchSignature", "SearchString",
    "ModuleStatus", "GetProcessAddress", "DisassembleCode", "AddCalculator",
    "SubCalculator", "PatchBytes", "Fill", "SetField", "GetField", "SectionSetData",
    "AddSection", "RemoveSection", "RenameSection", "SetChecksum", "Revert",
    "EditStatus", "Save", "Entropy", "Hash", "RichHeader", "Tls", "DebugInfo",
    "LoadConfig", "Certificate", "HealthCheck", "SectionLayout", "Overlay",
    "ComparePE", "ExtractStrings", "ExportSymbols", "SetEntryPoint",
    "SetSectionFlags", "ResizeSection", "AppendToSection", "ZeroSection",
    "ExtractSection", "AppendOverlay", "RemoveOverlay", "StripCertificate",
    "StripRelocations", "SetTimestamp", "PatchIAT", "SetDataDirectory",
    "SetDosStub", "SetImageBase", "AddRelocation", "DisassembleAt",
    "SearchPattern", "FindFunctionBounds", "XrefsScan", "InstructionStats",
    "Assemble", "AssemblePatch", "NopInstructions", "ReplaceInstruction",
    "DisassembleFunction", "CodeCaveScan", "PatchCall", "ClearRichHeader",
    "AddImport", "SetCertificate", "AddTLSCallback", "ClearDataDirectory",
    "SetDllCharacteristics", "StripDebugInfo", "SetSubsystem",
    "StripBoundImports", "SetSectionRawData", "SetImageVersion",
    "FixSectionAlignment", "RemoveSectionTableEntry", "SetSizeOfStack",
    "PESignatureScan", "ReviveImport", "DosHeaderDetail", "SectionEntropyMap",
    "FindCodeCavesAll", "CallGraph", "ImportSummary", "VersionResources",
    "ImportTimestamp", "TlsCallbacksAll", "DebugTypeDetail", "ManifestResource",
    "ComDescriptor", "ForwarderMap", "ExceptionTable", "ExportDetail",
    "UnwindInfo", "DelayImport", "SetResourceData", "SetEntryPointSection",
    "RebuildRelocations", "SetLoadConfigGuard", "PatchExportRva", "AddResource",
    "SetRichHeaderKey", "UpdateChecksums", "SecurityAudit", "AuthenticodeInfo",
    "CodeViewInfo", "SectionPermissions", "ImportHash", "OverlayHash",
    "SehHandlerTable", "GuardFlagsDetail", "ResourceTypeStats",
    "RelocationStats", "HashAll", "HashEachSection", "HashRange", "FileChecksum",
    "RichChecksum", "ImportHashEx", "AuthenticodeHash", "VerifySignature",
    "SessionCreate", "SessionList", "SessionClose", "Close",
)

class Config:
    """连接配置。

    api_key 对应服务端鉴权（X-Auth-Token 头）。
    未显式传入时依次取：环境变量 PEDAGGER_TOKEN -> 内置默认 KEY DEFAULT_API_KEY。
    """

    def __init__(self, address: str = "127.0.0.1", port: int = DEFAULT_PORT,
                 api_key: Optional[str] = None, session: Optional[str] = None):
        self.address = address
        self.port = port
        self.server_addr = "http://{}:{}".format(address, port)
        self.api_key = api_key if api_key is not None else _default_api_key()
        self.timeout = 5
        # 会话 id；为空则走服务端的默认（当前）会话
        self.session = session

    def set_server(self, address: str, port: int = DEFAULT_PORT) -> None:
        self.address = address
        self.port = port
        self.server_addr = "http://{}:{}".format(address, port)

    def set_api_key(self, api_key: Optional[str]) -> None:
        """设置鉴权 token；传 None 或空串表示恢复内置默认 KEY（不会回退到环境变量）。"""
        self.api_key = api_key or DEFAULT_API_KEY

    def set_session(self, session: Optional[str]) -> None:
        self.session = session or None

    def is_server_available(self, timeout: Optional[int] = None) -> bool:
        timeout = timeout or self.timeout
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((self.address, self.port))
                return result == 0
        except socket.error as e:
            print("WARNING: Server check failed: {}".format(str(e)))
            return False

class BaseHttpClient:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        parsed_url = urlparse(self.config.server_addr)
        self.address = parsed_url.hostname
        self.port = parsed_url.port
        self.scheme = parsed_url.scheme
        self.path = parsed_url.path or '/'
        self.verify_ssl = True

    def set_server(self, address: str, port: int = DEFAULT_PORT) -> None:
        self.config.set_server(address, port)
        self.address = address
        self.port = port

    def set_api_key(self, api_key: str) -> None:
        self.config.set_api_key(api_key)

    def set_session(self, session: Optional[str]) -> None:
        self.config.set_session(session)

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        token = getattr(self.config, "api_key", "") or DEFAULT_API_KEY
        if token:
            headers["X-Auth-Token"] = token
        return headers

    def custom_post(self, payload: Optional[Dict] = None,
                    timeout: Optional[int] = None) -> str:
        import http.client
        headers = self._headers()
        body = json.dumps(payload).encode("utf-8") if payload else None
        timeout = timeout or self.config.timeout
        try:
            if self.scheme == "https":
                import ssl
                context = ssl._create_unverified_context() if not self.verify_ssl else None
                conn = http.client.HTTPSConnection(self.address, self.port, timeout=timeout, context=context)
            else:
                conn = http.client.HTTPConnection(self.address, self.port, timeout=timeout)
            conn.request("POST", self.path, body=body, headers=headers)
            response = conn.getresponse()
            response_text = response.read().decode("utf-8", errors="ignore")
            conn.close()
            return response_text
        except socket.timeout:
            return json.dumps({"status": "error", "message": "Request timed out"}, ensure_ascii=False)
        except ConnectionRefusedError:
            return json.dumps({"status": "error", "message": "Connection refused by server"}, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"status": "error", "message": "Request failed: {}".format(str(e))},
                              ensure_ascii=False)

    def custom_get(self, timeout: Optional[int] = None) -> str:
        """GET / —— 取服务端 plugin_info（版本、接口数、会话 TTL 等）。"""
        import http.client
        headers = self._headers()
        timeout = timeout or self.config.timeout
        try:
            if self.scheme == "https":
                import ssl
                context = ssl._create_unverified_context() if not self.verify_ssl else None
                conn = http.client.HTTPSConnection(self.address, self.port, timeout=timeout, context=context)
            else:
                conn = http.client.HTTPConnection(self.address, self.port, timeout=timeout)
            conn.request("GET", self.path, headers=headers)
            response = conn.getresponse()
            response_text = response.read().decode("utf-8", errors="ignore")
            conn.close()
            return response_text
        except socket.timeout:
            return json.dumps({"status": "error", "message": "Request timed out"}, ensure_ascii=False)
        except ConnectionRefusedError:
            return json.dumps({"status": "error", "message": "Connection refused by server"}, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"status": "error", "message": "Request failed: {}".format(str(e))},
                              ensure_ascii=False)

    def call(self, interface: str, params: Optional[Sequence] = None,
             session: Optional[str] = None, timeout: Optional[int] = None) -> str:
        """通用调用入口：任何接口都可以直接走这里。"""
        if interface not in SUPPORTED_INTERFACES:
            raise ValueError("unsupported interface: {}".format(interface))
        payload: Dict[str, Any] = {
            "interface": interface,
            "params": [("" if p is None else str(p)) for p in (params or [])],
        }
        sid = session if session is not None else getattr(self.config, "session", None)
        if sid:
            payload["session"] = str(sid)
        return self.custom_post(payload, timeout)

    def call_json(self, interface: str, params: Optional[Sequence] = None,
                  session: Optional[str] = None,
                  timeout: Optional[int] = None) -> Optional[Dict]:
        """同 call()，但直接返回解析后的 dict。"""
        return parse_response(self.call(interface, params, session, timeout))

class ServiceApi(BaseHttpClient):
    """服务信息接口。"""

    @check_server_available
    def system_info(self) -> str:
        """GET / —— 服务端 plugin_info（版本 / 接口数 / 会话 TTL / 鉴权与只读开关）。"""
        return self.custom_get()

class SessionApi(BaseHttpClient):
    """会话 / 文件管理：Open、Close、SessionCreate、SessionList、SessionClose。"""

    @check_server_available
    def open_file(self, file_path: str, session: Optional[str] = None) -> str:
        """Open —— 打开 PE 文件（必须用绝对路径）。"""
        return self.call("Open", _pack(file_path), session)

    @check_server_available
    def close_file(self, session: Optional[str] = None) -> str:
        """Close —— 关闭当前已打开的 PE 文件并释放资源。"""
        return self.call("Close", [], session)

    @check_server_available
    def session_create(self) -> str:
        """SessionCreate —— 新建会话，返回 session_id。"""
        return self.call("SessionCreate", [])

    @check_server_available
    def session_list(self) -> str:
        """SessionList —— 列出全部会话（id / 是否当前 / 是否打开 / 文件路径 / 修改计数）。"""
        return self.call("SessionList", [])

    @check_server_available
    def session_close(self, session_id: Optional[str] = None) -> str:
        """SessionClose —— 关闭指定会话；省略则关闭当前会话。"""
        return self.call("SessionClose", _pack(session_id))

class HeaderApi(BaseHttpClient):
    """PE 头与基础结构只读解析。"""

    @check_server_available
    def file_basic_info(self, session: Optional[str] = None) -> str:
        """FileBasicInfo —— 文件基本信息（大小、时间戳、机器类型、PE 类型等）。"""
        return self.call("FileBasicInfo", [], session)

    @check_server_available
    def dos_head(self, session: Optional[str] = None) -> str:
        """DosHead —— IMAGE_DOS_HEADER 全字段。"""
        return self.call("DosHead", [], session)

    @check_server_available
    def nt_head(self, session: Optional[str] = None) -> str:
        """NtHead —— IMAGE_NT_HEADERS（含 FileHeader / OptionalHeader）。"""
        return self.call("NtHead", [], session)

    @check_server_available
    def section(self, session: Optional[str] = None) -> str:
        """Section —— 节表全字段。"""
        return self.call("Section", [], session)

    @check_server_available
    def optional_data_directory(self, session: Optional[str] = None) -> str:
        """OptionalDataDirectory —— 16 个数据目录项。"""
        return self.call("OptionalDataDirectory", [], session)

    @check_server_available
    def module_status(self, session: Optional[str] = None) -> str:
        """ModuleStatus —— 链接器版本、校验和、DllCharacteristics 等状态位。"""
        return self.call("ModuleStatus", [], session)

    @check_server_available
    def resource(self, session: Optional[str] = None) -> str:
        """Resource —— 资源目录树。"""
        return self.call("Resource", [], session)

    @check_server_available
    def dos_header_detail(self, max_insns: Union[int, str],
                          session: Optional[str] = None) -> str:
        """DosHeaderDetail —— DOS 头/存根深度解析，max_insns 为反汇编指令上限。"""
        return self.call("DosHeaderDetail", _exact(1, max_insns), session)

class AddressApi(BaseHttpClient):
    """地址换算：VA / RVA / FOA 互转。"""

    @check_server_available
    def va_to_foa(self, va: Union[int, str], session: Optional[str] = None) -> str:
        """VAToFOA —— 虚拟地址转文件偏移。"""
        return self.call("VAToFOA", _pack(_addr(va, "VA")), session)

    @check_server_available
    def rva_to_foa(self, rva: Union[int, str], session: Optional[str] = None) -> str:
        """RVAToFOA —— 相对虚拟地址转文件偏移。"""
        return self.call("RVAToFOA", _pack(_addr(rva, "RVA")), session)

    @check_server_available
    def foa_to_va(self, foa: Union[int, str], session: Optional[str] = None) -> str:
        """FOAToVA —— 文件偏移转虚拟地址。"""
        return self.call("FOAToVA", _pack(_addr(foa, "FOA")), session)

    @check_server_available
    def va_to_rva(self, va: Union[int, str], session: Optional[str] = None) -> str:
        """VAToRVA —— 虚拟地址转相对虚拟地址。"""
        return self.call("VAToRVA", _pack(_addr(va, "VA")), session)

    @check_server_available
    def rva_to_va(self, rva: Union[int, str], session: Optional[str] = None) -> str:
        """RVAToVA —— 相对虚拟地址转虚拟地址。"""
        return self.call("RVAToVA", _pack(_addr(rva, "RVA")), session)

class MemoryApi(BaseHttpClient):
    """内存/数据读取、搜索与字节改写。"""

    @check_server_available
    def hex_ascii(self, start_addr: Union[int, str], addr_len: Union[int, str],
                  session: Optional[str] = None) -> str:
        """HexASCII —— 十六进制转储（起始地址 + 长度）。"""
        return self.call("HexASCII", _pack(_addr(start_addr, "start"), addr_len), session)

    @check_server_available
    def search_signature(self, start_addr: Union[int, str], search_len: Union[int, str],
                         signature: str, session: Optional[str] = None) -> str:
        """SearchSignature —— 特征码搜索，signature 形如 "4D 5A 90 00"。"""
        return self.call("SearchSignature",
                         _pack(_addr(start_addr, "start"), search_len, signature), session)

    @check_server_available
    def search_string(self, start_addr: Union[int, str], search_len: Union[int, str],
                      target_str: str, session: Optional[str] = None) -> str:
        """SearchString —— 字符串搜索。"""
        return self.call("SearchString",
                         _pack(_addr(start_addr, "start"), search_len, target_str), session)

    @check_server_available
    def search_pattern(self, pattern: str, max_results: Optional[Union[int, str]] = None,
                       session: Optional[str] = None) -> str:
        """SearchPattern —— 带 ? 通配符的模式搜索。"""
        return self.call("SearchPattern", _pack(pattern, max_results), session)

    @check_server_available
    def extract_strings(self, min_length: Optional[Union[int, str]] = None,
                        encoding: Optional[str] = None,
                        section: Optional[str] = None,
                        session: Optional[str] = None) -> str:
        """ExtractStrings —— 抽取可打印字符串，encoding: ascii|unicode|both。"""
        return self.call("ExtractStrings", _pack(min_length, encoding, section), session)

    @check_server_available
    def get_process_address(self, dll_name: str, function: str,
                            session: Optional[str] = None) -> str:
        """GetProcessAddress —— 查询指定 DLL 导出函数的运行时地址。"""
        return self.call("GetProcessAddress", _pack(dll_name, function), session)

    @check_server_available
    def patch_bytes(self, address_type: str, address: Union[int, str],
                    hex_byte_string: str, session: Optional[str] = None) -> str:
        """PatchBytes —— 写入字节，address_type: foa|rva|va。"""
        return self.call("PatchBytes",
                         _pack(address_type, _addr(address, "address"), hex_byte_string), session)

    @check_server_available
    def fill(self, address_type: str, address: Union[int, str], size: Union[int, str],
             byte_value: Union[int, str], session: Optional[str] = None) -> str:
        """Fill —— 区间填充，address_type: foa|rva|va。"""
        return self.call("Fill",
                         _pack(address_type, _addr(address, "address"), size, byte_value), session)

    @check_server_available
    def code_cave_scan(self, min_size: Optional[Union[int, str]] = None,
                       max_results: Optional[Union[int, str]] = None,
                       session: Optional[str] = None) -> str:
        """CodeCaveScan —— 扫描空洞区域。"""
        return self.call("CodeCaveScan", _pack(min_size, max_results), session)

    @check_server_available
    def find_code_caves_all(self, min_size: Union[int, str],
                            session: Optional[str] = None) -> str:
        """FindCodeCavesAll —— 全文件空洞扫描。"""
        return self.call("FindCodeCavesAll", _exact(1, min_size), session)

class FieldApi(BaseHttpClient):
    """PE 字段级读写。"""

    @check_server_available
    def set_field(self, field_name: str, value: Union[int, str],
                  session: Optional[str] = None) -> str:
        """SetField —— 按字段名写入（如 AddressOfEntryPoint）。"""
        return self.call("SetField", _pack(field_name, value), session)

    @check_server_available
    def get_field(self, field_name: str, session: Optional[str] = None) -> str:
        """GetField —— 按字段名读取。"""
        return self.call("GetField", _pack(field_name), session)

class SectionApi(BaseHttpClient):
    """节区相关：增删改名、属性、导出、对齐、熵图。"""

    @check_server_available
    def section_set_data(self, section: str, hex_byte_string: str,
                         session: Optional[str] = None) -> str:
        """SectionSetData —— 覆写节原始数据。"""
        return self.call("SectionSetData", _pack(section, hex_byte_string), session)

    @check_server_available
    def add_section(self, name: str, virtual_size: Optional[Union[int, str]] = None,
                    characteristics: Optional[Union[int, str]] = None,
                    hex_byte_string: Optional[str] = None,
                    session: Optional[str] = None) -> str:
        """AddSection —— 新增节（name 最长 8 字符）。"""
        return self.call("AddSection",
                         _pack(name, virtual_size, characteristics, hex_byte_string), session)

    @check_server_available
    def remove_section(self, section: str, clear_raw_data: Optional[Union[str, bool]] = None,
                       session: Optional[str] = None) -> str:
        """RemoveSection —— 删除节，clear_raw_data: true|false。"""
        if isinstance(clear_raw_data, bool):
            clear_raw_data = "true" if clear_raw_data else "false"
        return self.call("RemoveSection", _pack(section, clear_raw_data), session)

    @check_server_available
    def rename_section(self, section: str, new_name: str,
                       session: Optional[str] = None) -> str:
        """RenameSection —— 节改名（new_name 最长 8 字符）。"""
        return self.call("RenameSection", _pack(section, new_name), session)

    @check_server_available
    def set_section_flags(self, section: str, set_mask: Optional[Union[int, str]] = None,
                          clear_mask: Optional[Union[int, str]] = None,
                          session: Optional[str] = None) -> str:
        """SetSectionFlags —— 置位/清位节属性。"""
        return self.call("SetSectionFlags", _pack(section, set_mask, clear_mask), session)

    @check_server_available
    def resize_section(self, section: str, virtual_size: Optional[Union[int, str]] = None,
                       raw_size: Optional[Union[int, str]] = None,
                       session: Optional[str] = None) -> str:
        """ResizeSection —— 调整节的虚拟大小/原始大小。"""
        return self.call("ResizeSection", _pack(section, virtual_size, raw_size), session)

    @check_server_available
    def append_to_section(self, section: str, hex_byte_string: str,
                          session: Optional[str] = None) -> str:
        """AppendToSection —— 在节尾追加数据。"""
        return self.call("AppendToSection", _pack(section, hex_byte_string), session)

    @check_server_available
    def zero_section(self, section: str, fill_value: Optional[Union[int, str]] = None,
                     session: Optional[str] = None) -> str:
        """ZeroSection —— 清零/填充整个节，fill_value: 0..255。"""
        return self.call("ZeroSection", _pack(section, fill_value), session)

    @check_server_available
    def extract_section(self, section: str, output_path: str,
                        session: Optional[str] = None) -> str:
        """ExtractSection —— 导出节内容到文件。"""
        return self.call("ExtractSection", _pack(section, output_path), session)

    @check_server_available
    def set_section_raw_data(self, section: str, hex_data: str,
                             session: Optional[str] = None) -> str:
        """SetSectionRawData —— 直接覆写节原始数据。"""
        return self.call("SetSectionRawData", _exact(2, section, hex_data), session)

    @check_server_available
    def remove_section_table_entry(self, section: str, fix_dirs: Union[int, str, bool],
                                   session: Optional[str] = None) -> str:
        """RemoveSectionTableEntry —— 删除节表项，fix_dirs: 0|1 是否同步修正数据目录。"""
        if isinstance(fix_dirs, bool):
            fix_dirs = 1 if fix_dirs else 0
        return self.call("RemoveSectionTableEntry", _exact(2, section, fix_dirs), session)

    @check_server_available
    def section_layout(self, session: Optional[str] = None) -> str:
        """SectionLayout —— 节布局分析（重叠、间隙、对齐）。"""
        return self.call("SectionLayout", [], session)

    @check_server_available
    def section_permissions(self, session: Optional[str] = None) -> str:
        """SectionPermissions —— 节权限矩阵（RWX）。"""
        return self.call("SectionPermissions", [], session)

    @check_server_available
    def section_entropy_map(self, block_size: Union[int, str],
                            session: Optional[str] = None) -> str:
        """SectionEntropyMap —— 分块熵图。"""
        return self.call("SectionEntropyMap", _exact(1, block_size), session)

    @check_server_available
    def fix_section_alignment(self, file_align: Optional[Union[int, str]] = None,
                              section_align: Optional[Union[int, str]] = None,
                              session: Optional[str] = None) -> str:
        """FixSectionAlignment —— 修正文件对齐/节对齐。"""
        return self.call("FixSectionAlignment", _exact(2, file_align, section_align), session)

class ImportApi(BaseHttpClient):
    """导入表相关解析与改写。"""

    @check_server_available
    def import_by_dll(self, session: Optional[str] = None) -> str:
        """ImportByDll —— 按 DLL 聚合的导入表。"""
        return self.call("ImportByDll", [], session)

    @check_server_available
    def import_by_name(self, dll_name: str, session: Optional[str] = None) -> str:
        """ImportByName —— 列出某个 DLL 的导入函数。"""
        return self.call("ImportByName", _pack(dll_name), session)

    @check_server_available
    def import_by_function(self, func_name: str,
                           case_sensitive: Optional[Union[str, bool]] = None,
                           check_ordinal: Optional[Union[str, bool]] = None,
                           session: Optional[str] = None) -> str:
        """ImportByFunction —— 按函数名反查来源。"""
        if isinstance(case_sensitive, bool):
            case_sensitive = "true" if case_sensitive else "false"
        if isinstance(check_ordinal, bool):
            check_ordinal = "true" if check_ordinal else "false"
        return self.call("ImportByFunction", _pack(func_name, case_sensitive, check_ordinal), session)

    @check_server_available
    def import_all(self, session: Optional[str] = None) -> str:
        """ImportAll —— 全量导入表。"""
        return self.call("ImportAll", [], session)

    @check_server_available
    def import_summary(self, session: Optional[str] = None) -> str:
        """ImportSummary —— 导入表汇总（按 DLL 计数、可疑项）。"""
        return self.call("ImportSummary", [], session)

    @check_server_available
    def import_timestamp(self, session: Optional[str] = None) -> str:
        """ImportTimestamp —— 导入表时间戳与绑定信息。"""
        return self.call("ImportTimestamp", [], session)

    @check_server_available
    def import_hash(self, session: Optional[str] = None) -> str:
        """ImportHash —— 导入表哈希（imphash）。"""
        return self.call("ImportHash", [], session)

    @check_server_available
    def import_hash_ex(self, extended: Optional[Union[int, str]] = None,
                       session: Optional[str] = None) -> str:
        """ImportHashEx —— 扩展导入表哈希，extended: 0|1（默认 1）。"""
        return self.call("ImportHashEx", _exact(1, extended), session)

    @check_server_available
    def forwarder_map(self, session: Optional[str] = None) -> str:
        """ForwarderMap —— 导出转发链。"""
        return self.call("ForwarderMap", [], session)

    @check_server_available
    def delay_import(self, session: Optional[str] = None) -> str:
        """DelayImport —— 延迟导入表。"""
        return self.call("DelayImport", [], session)

    @check_server_available
    def add_import(self, dll_name: str, func_name_or_ordinal: str,
                   session: Optional[str] = None) -> str:
        """AddImport —— 新增导入项。"""
        return self.call("AddImport", _pack(dll_name, func_name_or_ordinal), session)

    @check_server_available
    def patch_iat(self, dll_name_filter: str, function_name: str, value: Union[int, str],
                  session: Optional[str] = None) -> str:
        """PatchIAT —— 改写 IAT 项。

        dll_name_filter 需传**完整 DLL 名**（如 "ntdll.dll"）；传 "ntdll"
        这种去后缀的写法匹配不到，会报 "No matching import entry was found"。
        """
        return self.call("PatchIAT", _pack(dll_name_filter, function_name, value), session)

    @check_server_available
    def revive_import(self, max_insns: Union[int, str],
                      session: Optional[str] = None) -> str:
        """ReviveImport —— 从代码中重建疑似导入调用。"""
        return self.call("ReviveImport", _exact(1, max_insns), session)

class ExportApi(BaseHttpClient):
    """导出表相关解析与改写。"""

    @check_server_available
    def export(self, session: Optional[str] = None) -> str:
        """Export —— 导出表。"""
        return self.call("Export", [], session)

    @check_server_available
    def export_detail(self, name_filter: Optional[str] = None,
                      session: Optional[str] = None) -> str:
        """ExportDetail —— 导出表详情，name_filter 为空表示全部。"""
        return self.call("ExportDetail", _exact(1, name_filter), session)

    @check_server_available
    def export_symbols(self, fmt: Optional[str] = None,
                       session: Optional[str] = None) -> str:
        """ExportSymbols —— 导出符号，fmt: json|idc|def|cheader。"""
        return self.call("ExportSymbols", _pack(fmt), session)

    @check_server_available
    def patch_export_rva(self, symbol: str, new_rva: Union[int, str],
                         forwarder: Optional[str] = None,
                         session: Optional[str] = None) -> str:
        """PatchExportRva —— 改写导出符号 RVA，forwarder 非空则写成转发。"""
        return self.call("PatchExportRva",
                         _exact(3, symbol, _addr(new_rva, "new_rva"), forwarder), session)

class RelocApi(BaseHttpClient):
    """重定位表相关。"""

    @check_server_available
    def fix_reloc_page(self, session: Optional[str] = None) -> str:
        """FixRelocPage —— 重定位分页视图。"""
        return self.call("FixRelocPage", [], session)

    @check_server_available
    def fix_reloc(self, target: str, session: Optional[str] = None) -> str:
        """FixReloc —— 重定位明细，target: all 或十六进制 RVA（如 0x1000）。"""
        return self.call("FixReloc", _exact(1, target), session)

    @check_server_available
    def add_relocation(self, rva: Union[int, str], relocation_type: Optional[Union[int, str]] = None,
                       session: Optional[str] = None) -> str:
        """AddRelocation —— 追加一条重定位项。

        仅当重定位目录**位于文件末尾**时才允许就地追加；若其后还有其他数据
        （签名、overlay 等），服务端会拒绝，以免移动数据后头部偏移不变而静默
        损坏文件。
        """
        return self.call("AddRelocation", _pack(_addr(rva, "rva"), relocation_type), session)

    @check_server_available
    def strip_relocations(self, session: Optional[str] = None) -> str:
        """StripRelocations —— 移除重定位表。"""
        return self.call("StripRelocations", [], session)

    @check_server_available
    def rebuild_relocations(self, section: str, scan_limit: Optional[Union[int, str]] = None,
                            session: Optional[str] = None) -> str:
        """RebuildRelocations —— 重建重定位表。

        注意：section 指的是**重定位表所在的节**（通常是 .reloc，留空即默认
        .reloc），不是"要扫描哪些代码"。传 .text 会去把 .text 的原始数据当
        重定位块解析，必然报 "no usable entries to rebuild from"。
        """
        return self.call("RebuildRelocations", _exact(2, section, scan_limit), session)

    @check_server_available
    def relocation_stats(self, session: Optional[str] = None) -> str:
        """RelocationStats —— 重定位统计（类型分布、页数）。"""
        return self.call("RelocationStats", [], session)

class DisasmApi(BaseHttpClient):
    """反汇编 / 汇编 / 控制流分析 / 指令级改写。"""

    @check_server_available
    def disassemble_code(self, start_foa: Union[int, str], disasm_len: Union[int, str],
                         session: Optional[str] = None) -> str:
        """DisassembleCode —— 从文件偏移开始反汇编。"""
        return self.call("DisassembleCode", _pack(_addr(start_foa, "start_foa"), disasm_len), session)

    @check_server_available
    def disassemble_at(self, address_type: str, address: Union[int, str],
                       size: Optional[Union[int, str]] = None,
                       count: Optional[Union[int, str]] = None,
                       session: Optional[str] = None) -> str:
        """DisassembleAt —— 指定地址反汇编，address_type: foa|rva|va。"""
        return self.call("DisassembleAt",
                         _pack(address_type, _addr(address, "address"), size, count), session)

    @check_server_available
    def disassemble_function(self, address_type: str, address: Union[int, str],
                             max_instructions: Optional[Union[int, str]] = None,
                             session: Optional[str] = None) -> str:
        """DisassembleFunction —— 函数体反汇编。"""
        return self.call("DisassembleFunction",
                         _pack(address_type, _addr(address, "address"), max_instructions), session)

    @check_server_available
    def find_function_bounds(self, address_type: str, address: Union[int, str],
                             session: Optional[str] = None) -> str:
        """FindFunctionBounds —— 推断函数起止边界。"""
        return self.call("FindFunctionBounds",
                         _pack(address_type, _addr(address, "address")), session)

    @check_server_available
    def xrefs_scan(self, address_type: str, address: Union[int, str],
                   max_results: Optional[Union[int, str]] = None,
                   session: Optional[str] = None) -> str:
        """XrefsScan —— 交叉引用扫描。"""
        return self.call("XrefsScan",
                         _pack(address_type, _addr(address, "address"), max_results), session)

    @check_server_available
    def instruction_stats(self, address_type: str, address: Union[int, str],
                          size: Optional[Union[int, str]] = None,
                          session: Optional[str] = None) -> str:
        """InstructionStats —— 指令统计（助记符分布、分组）。"""
        return self.call("InstructionStats",
                         _pack(address_type, _addr(address, "address"), size), session)

    @check_server_available
    def assemble(self, instructions: str, cip: Optional[Union[int, str]] = None,
                 mode: Optional[str] = None, session: Optional[str] = None) -> str:
        """Assemble —— 汇编指令串为字节码（不落盘）。

        mode 只能取 "x86" / "x64"，传别的（包括 "0"）会报
        Unknown mode；留空则按当前 PE 的位数自动判断。
        """
        return self.call("Assemble", _pack(instructions, cip, mode), session)

    @check_server_available
    def assemble_patch(self, address_type: str, address: Union[int, str],
                       instructions: str, update_checksum: Optional[Union[int, str]] = None,
                       session: Optional[str] = None) -> str:
        """AssemblePatch —— 汇编并就地打补丁。"""
        return self.call("AssemblePatch",
                         _pack(address_type, _addr(address, "address"), instructions, update_checksum),
                         session)

    @check_server_available
    def nop_instructions(self, address_type: str, address: Union[int, str],
                         instruction_count: Union[int, str],
                         session: Optional[str] = None) -> str:
        """NopInstructions —— 把 N 条指令替换为 nop。"""
        return self.call("NopInstructions",
                         _pack(address_type, _addr(address, "address"), instruction_count), session)

    @check_server_available
    def replace_instruction(self, address_type: str, address: Union[int, str],
                            new_instruction: str, session: Optional[str] = None) -> str:
        """ReplaceInstruction —— 用新指令替换原指令。"""
        return self.call("ReplaceInstruction",
                         _pack(address_type, _addr(address, "address"), new_instruction), session)

    @check_server_available
    def patch_call(self, address_type: str, address: Union[int, str],
                   new_target: Union[int, str], session: Optional[str] = None) -> str:
        """PatchCall —— 改写 call/jmp 目标。

        只支持**直接相对转移**（`call 0x23357` 这类）。若该地址是指令是间
        接调用（`call qword ptr [rip + ...]`）或不是转移指令，服务端会拒绝。
        new_target 按运行时地址解释：>= ImageBase 视为 VA，否则视为 RVA。
        """
        return self.call("PatchCall",
                         _pack(address_type, _addr(address, "address"), _addr(new_target, "new_target")),
                         session)

    @check_server_available
    def call_graph(self, max_depth: Union[int, str], max_nodes: Union[int, str],
                   session: Optional[str] = None) -> str:
        """CallGraph —— 调用图（深度/节点上限）。"""
        return self.call("CallGraph", _exact(2, max_depth, max_nodes), session)

class EditApi(BaseHttpClient):
    """PE 结构改写（会进入编辑日志，需 Save 落盘）。"""

    @check_server_available
    def set_checksum(self, session: Optional[str] = None) -> str:
        """SetChecksum —— 重算并写入 OptionalHeader.CheckSum。"""
        return self.call("SetChecksum", [], session)

    @check_server_available
    def revert(self, session: Optional[str] = None) -> str:
        """Revert —— 撤销全部未保存修改。"""
        return self.call("Revert", [], session)

    @check_server_available
    def edit_status(self, session: Optional[str] = None) -> str:
        """EditStatus —— 当前编辑状态与修改日志。"""
        return self.call("EditStatus", [], session)

    @check_server_available
    def save(self, output_path: Optional[str] = None,
             session: Optional[str] = None) -> str:
        """Save —— 落盘；省略 output_path 则覆盖原文件。"""
        return self.call("Save", _pack(output_path), session)

    @check_server_available
    def set_entry_point(self, address_type: str, address: Union[int, str],
                        session: Optional[str] = None) -> str:
        """SetEntryPoint —— 设置入口点，address_type: rva|va|foa。"""
        return self.call("SetEntryPoint", _pack(address_type, _addr(address, "address")), session)

    @check_server_available
    def set_entry_point_section(self, section: str, in_section_offset: Union[int, str],
                                session: Optional[str] = None) -> str:
        """SetEntryPointSection —— 以“节 + 节内偏移”设置入口点。"""
        return self.call("SetEntryPointSection", _exact(2, section, in_section_offset), session)

    @check_server_available
    def set_image_base(self, new_image_base: Union[int, str],
                       session: Optional[str] = None) -> str:
        """SetImageBase —— 修改映像基址。"""
        return self.call("SetImageBase", _pack(_addr(new_image_base, "image_base")), session)

    @check_server_available
    def set_image_version(self, image_major: Union[int, str], image_minor: Union[int, str],
                          linker_major: Union[int, str], linker_minor: Union[int, str],
                          session: Optional[str] = None) -> str:
        """SetImageVersion —— 修改映像版本与链接器版本。"""
        return self.call("SetImageVersion",
                         _exact(4, image_major, image_minor, linker_major, linker_minor), session)

    @check_server_available
    def set_timestamp(self, unix_timestamp: Optional[Union[int, str]] = None,
                      session: Optional[str] = None) -> str:
        """SetTimestamp —— 修改文件头时间戳；省略则置 0。"""
        return self.call("SetTimestamp", _pack(unix_timestamp), session)

    @check_server_available
    def set_subsystem(self, subsystem: Union[int, str], major_version: Union[int, str],
                      minor_version: Union[int, str], session: Optional[str] = None) -> str:
        """SetSubsystem —— 修改子系统及版本。"""
        return self.call("SetSubsystem", _exact(3, subsystem, major_version, minor_version), session)

    @check_server_available
    def set_dll_characteristics(self, set_mask: Union[int, str], clear_mask: Union[int, str],
                                session: Optional[str] = None) -> str:
        """SetDllCharacteristics —— 置位/清位 DllCharacteristics。"""
        return self.call("SetDllCharacteristics", _exact(2, set_mask, clear_mask), session)

    @check_server_available
    def set_size_of_stack(self, stack_reserve: Union[int, str], stack_commit: Union[int, str],
                          heap_reserve: Union[int, str], heap_commit: Union[int, str],
                          session: Optional[str] = None) -> str:
        """SetSizeOfStack —— 修改栈/堆保留与提交大小。"""
        return self.call("SetSizeOfStack",
                         _exact(4, stack_reserve, stack_commit, heap_reserve, heap_commit), session)

    @check_server_available
    def set_data_directory(self, index_or_name: str, rva: Union[int, str],
                           size: Optional[Union[int, str]] = None,
                           session: Optional[str] = None) -> str:
        """SetDataDirectory —— 修改数据目录项（如 export / import / load_config）。"""
        return self.call("SetDataDirectory", _pack(index_or_name, _addr(rva, "rva"), size), session)

    @check_server_available
    def clear_data_directory(self, directory_spec: str, mode: str,
                             session: Optional[str] = None) -> str:
        """ClearDataDirectory —— 清空/移除数据目录，mode: clear|remove。"""
        return self.call("ClearDataDirectory", _exact(2, directory_spec, mode), session)

    @check_server_available
    def set_dos_stub(self, hex_byte_string: str, session: Optional[str] = None) -> str:
        """SetDosStub —— 覆写 DOS 存根。"""
        return self.call("SetDosStub", _pack(hex_byte_string), session)

    @check_server_available
    def set_resource_data(self, resource_spec: str, hex_data: str,
                          session: Optional[str] = None) -> str:
        """SetResourceData —— 覆写资源项。

        resource_spec 是**三级路径** "type:name:lang"，各级可为数字 ID，也可
        用 RT_ 前缀的符号名（RT_ICON / RT_RCDATA / RT_VERSION …），例如
        "RT_RCDATA:1:1033"、"16:1:0x409"。只写 "0" 这类不完整路径会报
        "The specified resource entry was not found"。
        """
        return self.call("SetResourceData", _exact(2, resource_spec, hex_data), session)

    @check_server_available
    def add_resource(self, res_type: Union[int, str], name_id: Union[int, str],
                     language: Union[int, str], hex_data: str,
                     session: Optional[str] = None) -> str:
        """AddResource —— 追加资源项（只能在资源块尾部就地追加）。

        要求 type/name 这两级父目录**已存在**，否则报
        "The parent resource directory chain does not exist"。也就是说它只能
        往已有分支下加新 lang 项，无法凭空创建新的资源类型。
        """
        return self.call("AddResource", _exact(4, res_type, name_id, language, hex_data), session)

    @check_server_available
    def set_rich_header_key(self, new_key: Union[int, str],
                            session: Optional[str] = None) -> str:
        """SetRichHeaderKey —— 修改 Rich 头异或密钥。"""
        return self.call("SetRichHeaderKey", _exact(1, _addr(new_key, "new_key")), session)

    @check_server_available
    def clear_rich_header(self, update_checksum: Optional[Union[int, str]] = None,
                          session: Optional[str] = None) -> str:
        """ClearRichHeader —— 清除 Rich 头。"""
        return self.call("ClearRichHeader", _pack(update_checksum), session)

    @check_server_available
    def update_checksums(self, timestamp: Optional[Union[int, str]] = None,
                         session: Optional[str] = None) -> str:
        """UpdateChecksums —— 更新校验和，timestamp 为空则保留原值。"""
        return self.call("UpdateChecksums", _exact(1, timestamp), session)

    @check_server_available
    def strip_debug_info(self, zero_section: Union[int, str, bool],
                         session: Optional[str] = None) -> str:
        """StripDebugInfo —— 移除调试目录，zero_section: 0|1 是否同时清零对应节。"""
        if isinstance(zero_section, bool):
            zero_section = 1 if zero_section else 0
        return self.call("StripDebugInfo", _exact(1, zero_section), session)

    @check_server_available
    def strip_bound_imports(self, session: Optional[str] = None) -> str:
        """StripBoundImports —— 移除绑定导入表。"""
        return self.call("StripBoundImports", [], session)

    @check_server_available
    def strip_certificate(self, session: Optional[str] = None) -> str:
        """StripCertificate —— 移除数字签名（安全目录）。"""
        return self.call("StripCertificate", [], session)

    @check_server_available
    def set_certificate(self, cert_file_path: str,
                        update_checksum: Optional[Union[int, str]] = None,
                        session: Optional[str] = None) -> str:
        """SetCertificate —— 从文件写入数字签名。"""
        return self.call("SetCertificate", _pack(cert_file_path, update_checksum), session)

    @check_server_available
    def add_tls_callback(self, callback_va: Union[int, str],
                         session: Optional[str] = None) -> str:
        """AddTLSCallback —— 追加 TLS 回调。

        要求目标文件**已有 TLS 目录**（DataDirectory[9] 非空），否则报
        "This image has no TLS directory"。可先用 tls() 探测。
        """
        return self.call("AddTLSCallback", _pack(_addr(callback_va, "callback_va")), session)

    @check_server_available
    def set_load_config_guard(self, cookie_rva: Union[int, str],
                              se_handler_table_rva: Union[int, str],
                              session: Optional[str] = None) -> str:
        """SetLoadConfigGuard —— 设置 LoadConfig 的 SecurityCookie 与 SEH 表。"""
        return self.call("SetLoadConfigGuard",
                         _exact(2, _addr(cookie_rva, "cookie_rva"),
                               _addr(se_handler_table_rva, "se_handler_table_rva")), session)

    @check_server_available
    def append_overlay(self, hex_byte_string: str, session: Optional[str] = None) -> str:
        """AppendOverlay —— 追加附加数据（overlay）。"""
        return self.call("AppendOverlay", _pack(hex_byte_string), session)

    @check_server_available
    def remove_overlay(self, session: Optional[str] = None) -> str:
        """RemoveOverlay —— 移除附加数据。"""
        return self.call("RemoveOverlay", [], session)

class AnalyzeApi(BaseHttpClient):
    """深度解析 / 结构分析（只读）。"""

    @check_server_available
    def entropy(self, section: Optional[str] = None, session: Optional[str] = None) -> str:
        """Entropy —— 熵值；省略 section 为整文件。"""
        return self.call("Entropy", _pack(section), session)

    @check_server_available
    def hash(self, algorithm: Optional[str] = None, section: Optional[str] = None,
             session: Optional[str] = None) -> str:
        """Hash —— 哈希；algorithm: crc32|md5|sha1|sha256|fnv1a32|fnv1a64|all。"""
        return self.call("Hash", _pack(algorithm, section), session)

    @check_server_available
    def rich_header(self, session: Optional[str] = None) -> str:
        """RichHeader —— MSVC Rich 头（编译工具链指纹）。"""
        return self.call("RichHeader", [], session)

    @check_server_available
    def tls(self, session: Optional[str] = None) -> str:
        """Tls —— TLS 目录与回调。

        若目标文件没有 TLS 目录（DataDirectory[9] 为空，很多系统 DLL/EXE 都
        是这种情况），返回 error 而不是空结果。
        """
        return self.call("Tls", [], session)

    @check_server_available
    def debug_info(self, session: Optional[str] = None) -> str:
        """DebugInfo —— 调试目录。"""
        return self.call("DebugInfo", [], session)

    @check_server_available
    def load_config(self, session: Optional[str] = None) -> str:
        """LoadConfig —— 加载配置目录（SEH / CFG / Guard）。"""
        return self.call("LoadConfig", [], session)

    @check_server_available
    def certificate(self, session: Optional[str] = None) -> str:
        """Certificate —— 安全目录 / 签名证书。"""
        return self.call("Certificate", [], session)

    @check_server_available
    def health_check(self, session: Optional[str] = None) -> str:
        """HealthCheck —— 结构健康度体检。"""
        return self.call("HealthCheck", [], session)

    @check_server_available
    def overlay(self, action: Optional[str] = None, output_path: Optional[str] = None,
                session: Optional[str] = None) -> str:
        """Overlay —— 附加数据，action: info|hash|extract。"""
        return self.call("Overlay", _pack(action, output_path), session)

    @check_server_available
    def compare_pe(self, other_path: str, session: Optional[str] = None) -> str:
        """ComparePE —— 与另一个 PE 文件做结构对比。"""
        return self.call("ComparePE", _pack(other_path), session)

    @check_server_available
    def pe_signature_scan(self, category: Optional[str] = None,
                          max_hits: Optional[Union[int, str]] = None,
                          session: Optional[str] = None) -> str:
        """PESignatureScan —— 特征/指纹扫描。"""
        return self.call("PESignatureScan", _exact(2, category, max_hits), session)

    @check_server_available
    def version_resources(self, session: Optional[str] = None) -> str:
        """VersionResources —— VS_VERSION_INFO 资源。"""
        return self.call("VersionResources", [], session)

    @check_server_available
    def tls_callbacks_all(self, session: Optional[str] = None) -> str:
        """TlsCallbacksAll —— 全量 TLS 回调地址。"""
        return self.call("TlsCallbacksAll", [], session)

    @check_server_available
    def debug_type_detail(self, session: Optional[str] = None) -> str:
        """DebugTypeDetail —— 调试目录类型详情（CodeView / POGO 等）。"""
        return self.call("DebugTypeDetail", [], session)

    @check_server_available
    def manifest_resource(self, session: Optional[str] = None) -> str:
        """ManifestResource —— 清单资源（UAC / DPI / 依赖）。"""
        return self.call("ManifestResource", [], session)

    @check_server_available
    def com_descriptor(self, session: Optional[str] = None) -> str:
        """ComDescriptor —— .NET CLR 头。"""
        return self.call("ComDescriptor", [], session)

    @check_server_available
    def exception_table(self, session: Optional[str] = None) -> str:
        """ExceptionTable —— 异常处理表 / 运行时函数。"""
        return self.call("ExceptionTable", [], session)

    @check_server_available
    def unwind_info(self, rva: Union[int, str], session: Optional[str] = None) -> str:
        """UnwindInfo —— x64 unwind 信息（仅 x64/ARM64 有 exception 表）。

        rva 传 0 表示**列出全部条目**（最多 64 条）；传具体地址则只返回
        BeginAddress 恰好等于该 RVA 的那一条，找不到就报 "No exception table
        entry starts at the requested address"。
        """
        return self.call("UnwindInfo", _exact(1, _addr(rva, "rva")), session)

class SecurityApi(BaseHttpClient):
    """安全审计与签名验签。"""

    @check_server_available
    def security_audit(self, session: Optional[str] = None) -> str:
        """SecurityAudit —— 综合安全审计（ASLR / DEP / CFG / SEH 等）。"""
        return self.call("SecurityAudit", [], session)

    @check_server_available
    def authenticode_info(self, session: Optional[str] = None) -> str:
        """AuthenticodeInfo —— Authenticode 签名信息。"""
        return self.call("AuthenticodeInfo", [], session)

    @check_server_available
    def code_view_info(self, session: Optional[str] = None) -> str:
        """CodeViewInfo —— PDB 路径 / GUID / Age。"""
        return self.call("CodeViewInfo", [], session)

    @check_server_available
    def seh_handler_table(self, session: Optional[str] = None) -> str:
        """SehHandlerTable —— SEH 处理函数表。"""
        return self.call("SehHandlerTable", [], session)

    @check_server_available
    def guard_flags_detail(self, session: Optional[str] = None) -> str:
        """GuardFlagsDetail —— GuardFlags 逐位解析。"""
        return self.call("GuardFlagsDetail", [], session)

    @check_server_available
    def resource_type_stats(self, session: Optional[str] = None) -> str:
        """ResourceTypeStats —— 资源类型统计。"""
        return self.call("ResourceTypeStats", [], session)

    @check_server_available
    def overlay_hash(self, session: Optional[str] = None) -> str:
        """OverlayHash —— 附加数据哈希。"""
        return self.call("OverlayHash", [], session)

    @check_server_available
    def verify_signature(self, mode: Optional[str] = None,
                         session: Optional[str] = None) -> str:
        """VerifySignature —— 验签，mode: current|original（默认 current）。"""
        return self.call("VerifySignature", _pack(mode), session)

class HashApi(BaseHttpClient):
    """哈希摘要专项。"""

    @check_server_available
    def hash_all(self, target: Optional[str] = None, algos: Optional[str] = None,
                 session: Optional[str] = None) -> str:
        """HashAll —— 整体/节/区间哈希；target 形如 "" / ".text" / "range:foa:len"。"""
        return self.call("HashAll", _exact(2, target, algos), session)

    @check_server_available
    def hash_each_section(self, algos: Optional[str] = None,
                          session: Optional[str] = None) -> str:
        """HashEachSection —— 逐节哈希。"""
        return self.call("HashEachSection", _exact(1, algos), session)

    @check_server_available
    def hash_range(self, foa: Union[int, str], length: Union[int, str],
                   algos: Optional[str] = None, session: Optional[str] = None) -> str:
        """HashRange —— 指定区间哈希，length 传 0 表示到文件尾。"""
        return self.call("HashRange", _exact(3, _addr(foa, "foa"), length, algos), session)

    @check_server_available
    def file_checksum(self, timestamp: Optional[Union[int, str]] = None,
                      session: Optional[str] = None) -> str:
        """FileChecksum —— PE 头校验和。"""
        return self.call("FileChecksum", _exact(1, timestamp), session)

    @check_server_available
    def rich_checksum(self, timestamp: Optional[Union[int, str]] = None,
                      session: Optional[str] = None) -> str:
        """RichChecksum —— Rich 头校验和。"""
        return self.call("RichChecksum", _exact(1, timestamp), session)

    @check_server_available
    def authenticode_hash(self, algos: Optional[str] = None,
                          session: Optional[str] = None) -> str:
        """AuthenticodeHash —— Authenticode 计算用哈希（默认 sha1 + sha256）。"""
        return self.call("AuthenticodeHash", _exact(1, algos), session)

class CalcApi(BaseHttpClient):
    """辅助计算（DWORD64 加减，hex/dec/oct/bin 全进制输出）。"""

    @check_server_available
    def add_calculator(self, x: Union[int, str], y: Union[int, str],
                       session: Optional[str] = None) -> str:
        """AddCalculator —— x + y（modulo 2^64）。"""
        return self.call("AddCalculator", _pack(x, y), session)

    @check_server_available
    def sub_calculator(self, x: Union[int, str], y: Union[int, str],
                       session: Optional[str] = None) -> str:
        """SubCalculator —— x - y（modulo 2^64）。"""
        return self.call("SubCalculator", _pack(x, y), session)

class PEDaggerClient(
    ServiceApi,
    SessionApi,
    HeaderApi,
    AddressApi,
    MemoryApi,
    FieldApi,
    SectionApi,
    ImportApi,
    ExportApi,
    RelocApi,
    DisasmApi,
    EditApi,
    AnalyzeApi,
    SecurityApi,
    HashApi,
    CalcApi):
    """PEDagger 全功能客户端：聚合全部 142 个接口。"""

    def __init__(self, config: Optional[Config] = None, address: str = "",
                 port: int = DEFAULT_PORT, api_key: Optional[str] = None,
                 session: Optional[str] = None):
        if config is None:
            config = Config(address=address or "127.0.0.1", port=port,
                            api_key=api_key, session=session)
        else:
            if api_key:
                config.set_api_key(api_key)
            if session:
                config.set_session(session)
        super().__init__(config)

    def bind(self, address: str, port: int = DEFAULT_PORT,
             api_key: Optional[str] = None) -> "PEDaggerClient":
        """切换目标服务；api_key 为 None 时保留原有 token，传空串表示恢复内置默认 KEY。"""
        self.set_server(address, port)
        if api_key is not None:
            self.set_api_key(api_key)
        return self
