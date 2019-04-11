# OCP_Proto_for_Wireshark
## 安装使用方法

**在使用本插件前，请确保您的wireshark版本支持LUA.**

### Windows
将`ocp-wireshark-plug.lua` 文件拷贝至Wireshark安装目录下的plugins/VERSION 下面
如果 wireshark版本 `<= 2.4`, 您还需要编辑Wireshark安装目录下的init.lua文件，
在文件的最后加上以下代码以加载插件
```lua
-- for windows
dofile(DATA_DIR.."plugins\\YOUR_WIRESHARK_VERSION\\ocp-wireshark-plug.lua")
```
将`YOUR_WIRESHARK_VERSION`替换为具体的版本。

### Linux
将`ocp-wireshark-plug.lua` 文件拷贝至Wireshark安装目录(通常是 `/usr/share/wireshark`)下, 并在`init.lua`的末尾追加:
```lua
-- and for Linux
dofile(DATA_DIR.."ocp-wireshark-plug.lua")
```

## 使用方法

协议使用的是tcp，默认监听6664端口，通过在过滤条上输入`ocp`并回车，会只显示ocp的消息。
其他使用方法和其他协议一样。

**本插件只列举了部分AVP码，不识别的AVP会显示未unknow AVP，并显示其详细头部。一些不常用的group未展开。**


