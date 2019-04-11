-------------------------------------------
-- ocp diameter procol parser for wireshark
-------------------------------------------

local ocp_proto = Proto("ocp", 
						"China Telecom OCP");
local ocp_port = 6664;

-- DEFINE AVPS
local AVP_DEF = {
	["263"] = {["name"] = "Session-Id", ["type"] = "String"},
	["264"] = {["name"] = "Origin-Host", ["type"] = "String"},
	["296"] = {["name"] = "Origin-Realm", ["type"] = "String"},
	["283"] = {["name"] = "Destination-Realm", ["type"] = "String"},
	["258"] = {["name"] = "Auth-Application-Id", ["type"] = "Uint32"},
	["461"] = {["name"] = "Service-Context-Id", ["type"] = "String"},
	["80172"] = {["name"] = "Service-Flow-Id", ["type"] = "String"},
	["416"] = {["name"] = "CC-Request-Type", ["type"] = "Enum", ["Range"] = {
		[1] = "INITIAL_REQUEST", [2] = "UPDATE_REQUEST", 
		[3] = "TERMINATION_REQUEST", [4] = "EVENT_REQUEST"
	}},
	["415"] = {["name"] = "CC-Request-Number", ["type"] = "Uint32"},
	["293"] = {["name"] = "Destination-Host", ["type"] = "String"},
	["1"]   = {["name"] = "User-Name", ["type"] = "String"},
	["278"] = {["name"] = "Origin-State-Id", ["type"] = "Uint32"},
	["55"]  = {["name"] = "Event-Timestamp", ["type"] = "Uint32"},
	["443"] = {["name"] = "Subscription-Id", ["type"] = "Group"},
	["450"] = {["name"] = "Subscription-Id-Type", ["type"] = "Enum", ["Range"] = {
		[0] = "END_USER_E164",
		[1] = "END_USER_IMSI",
		[2] = "END_USER_SIP_URI",
		[3] = "END_USER_NAI",
		[4] = "END_USER_PRIVATE"
	}},
	["444"] = {["name"] = "Subscription-Id-Data", ["type"] = "String"},
	["21101"] = {["name"] = "ESN", ["type"] = "String"},
	["21102"] = {["name"] = "MEID", ["type"] = "String"},
	["295"] = {["name"] = "Termination-Cause", ["type"] = "Enum", ["Range"] = {
		[0] = "Unknown",
		[1] = "DIAMETER_LOGOUT",
		[2] = "DIAMETER_SERVICE_NOT_PROVIDED",
		[3] = "DIAMETER_BAD_ANSWER",
		[4] = "DIAMETER_ADMINISTRATIVE",
		[5] = "DIAMETER_LINK_BROKEN",
		[6] = "DIAMETER_AUTH_EXPIRED",
		[7] = "DIAMETER_USER_MOVED",
		[8] = "DIAMETER_SESSION_TIMEOUT"
	}},
	["282"] = {["name"] = "Route-Record", ["type"] = "String"},
	["439"] = {["name"] = "Service-Identifier", ["type"] = "Uint32"},
	["436"] = {["name"] = "Request-Action", ["type"] = "Enum", ["Range"] = {
		[0] = "DIRECT_DEBITING",
		[1] = "REFUND_ACCOUNT",
		[2] = "CHECK_BALANCE",
		[3] = "PRICE_ENQUIRY",
		[4] = "RATABLE_ENQUIRY",
		[5] = "HB_DEBITING",
		[6] = "Reserve_Request",
		[7] = "Reserve_Confirm",
		[8] = "Reserve_Cancel",
		[9] = "Service_AUTHORISE",
		[10] = "Service_UNAUTHORISE"
	}},
	["437"] = {["name"] = "Requested-Service-Unit", ["type"] = "Group"},
	["420"] = {["name"] = "CC-Time", ["type"] = "Uint32"},
	["413"] = {["name"] = "CC-mONEY", ["type"] = "Group"},
	["445"] = {["name"] = "Unit-Value", ["type"] = "Group"},
	["447"] = {["name"] = "Value-Digits", ["type"] = "Uint64"},
	["429"] = {["name"] = "Exponent", ["type"] = "Uint32"},
	["425"] = {["name"] = "Currency-Code", ["type"] = "Uint32"},
	["421"] = {["name"] = "CC-Total-Octets", ["type"] = "Uint64"},
	["412"] = {["name"] = "CC-Input-Octets", ["type"] = "Uint64"},
	["414"] = {["name"] = "CC-Output-Octets", ["type"] = "Uint64"},
	["417"] = {["name"] = "CC-Service-Specific-Units", ["type"] = "Uint64"},
	["20520"] = {["name"] = "Trial-Begin-Time", ["type"] = "Uint32"},
	["446"] = {["name"] = "Used-Service-Unit", ["type"] = "Group"},
	["872"] = {["name"] = "Reporting-Reason", ["type"] = "Enum", ["Range"] = {
		[0] = "THRESHOLD", [1] = "QHT", [2] = "FINAL",
		[3] = "QUOTA_EXHAUSTED", [4] = "VALIDITY_TIME",
		[5] = "QTHER_QUOTA_TYPE", [6] = "RATING_CONDITION_CHANGE",
		[7] = "FORCED_REAUTHORISATION", [8] = "POOL_EXHAUSTED"
	}},
	["870"] = {["name"] = "Trigger-Type", ["type"] = "Enum", ["Range"] = {
		[0] = "UNKNOWN",
		[1] = "CHANGE_IN_SGSN_IP_ADDRESS",
		[2] = "CHANGE_IN_QOS",
		[3] = "CHANGE_IN_LOCATION",
		[4] = "CHANGE_IN_RAT"
	}},
	["439"] = {["name"] = "Service-Identifier", ["type"] = "Uint32"},
	["437"] = {["name"] = "Request-Service-Uinit", ["type"] = "Group"},
	["413"] = {["name"] = "CC-Money", ["type"] = "Grouped"},
	["432"] = {["name"] = "Rating-Group", ["type"] = "Uint32"},
	["20513"] = {["name"] = "Product-Offer-Id", ["type"] = "String"},
	["1016"] = {["name"] = "QoS-Information", ["type"] = "Group"},
	["411"] = {["name"] = "CC-Correlation-Id", ["type"] = "String"},
	["458"] = {["name"] = "User-Equipment-Info", ["type"] = "Group"},
	["459"] = {["name"] = "User-Equipment-Info-type", ["type"] = "Uint32"},
	["460"] = {["name"] = "User-Equipment-Info-Value", ["type"] = "String"},
	["284"] = {["name"] = "Proxy-Info", ["type"] = "Group"},
	["280"] = {["name"] = "Proxy-Host", ["type"] = "String"},
	["33"]  = {["name"] = "proxy-State", ["type"] = "String"},
	["873"] = {["name"] = "Service-Infomation", ["type"] = "Group"},
	["874"] = {["name"] = "PS-Information", ["type"] = "Group"},
	["20300"] = {["name"] = "IN-Information", ["type"] = "Group"},
	["20400"] = {["name"] = "P2PSMS-Information", ["type"] = "Group"},
	["20500"] = {["name"] = "ISMP-Information", ["type"] = "Group"},
	["20600"] = {["name"] = "DSL-Information", ["type"] = "Group"},
	["20700"] = {["name"] = "PSTN-Event-Information", ["type"] = "Group"},
	["20800"] = {["name"] = "Recharge-Information", ["type"] = "Group"},
	["879"] = {["name"] = "POC-Information", ["type"] = "Group"},
	["22200"] = {["name"] = "IM-Information", ["type"] = "Group"},
	["876"] = {["name"] = "IMS-Information", ["type"] = "Group"},
	["5000"] = {["name"] = "Balance-Information", ["type"] = "Group"},
	["21000"] = {["name"] = "Auth-Service-Information", ["type"] = "Group"},
	["20329"] = {["name"] = "AoC-Information", ["type"] = "Group"},
	["20340"] = {["name"] = "AoC-Confirmation", ["type"] = "Enum", ["Range"] = {
		[0] = "no", [1] = "yes"
	}},
	["80047"] = {["name"] = "Forward-Info", ["type"] = "Group"},
	["80048"] = {["name"] = "Self-Host", ["type"] = "String"},
	["80049"] = {["name"] = "Downstream-Host", ["type"] = "String"},
	["80050"] = {["name"] = "Resonse-Time", ["type"] = "Uint32"},
	["268"] = {["name"] = "Result-Code", ["type"] = "Uint32"},
	["431"] = {["name"] = "Granted-Service-Unit", ["type"] = "Group"},
	["451"] = {["name"] = "Traffic-Time-Change", ["type"] = "Uint32"},
	["868"] = {["name"] = "Time-Quota-Threshold", ["type"] = "Uint64"},
	["869"] = {["name"] = "Volume-Quota-Threshold", ["type"] = "Uint64"},
	["423"] = {["name"] = "Cost-Information", ["type"] = "Group"},
	["424"] = {["name"] = "Cost-Unit", ["type"] = "String"},
	["430"] = {["name"] = "Final-Unit-Indication", ["type"] = "Group"},
	["449"] = {["name"] = "Final-Unit-Action", ["type"] = "Enum", ["Range"] = {
		[0] = "TERMINATE",
		[1] = "REDIRECT",
		[2] = "RESTRICT_ACCESS"
	}},
	["434"] = {["name"] = "Redirect-Server", ["type"] = "Group"},
	["433"] = {["name"] = "Enum", ["type"] = "Enum", ["Range"] = {
		[0] = "IPv4", [1] = "IPv6", [2] = "URL", [3] = "SIP URI"
	}},
	["435"] = {["name"] = "Redirect-Server-Address", ["type"] = "String"},
	["427"] = {["name"] = "Credit-Control-Failure-Handling", ["type"] = "Enum", ["Range"] = {
		[0] = "TERMINATE", [1] = "CONTINUE", [2] = "RETRY_AND_TERMINATE"
	}},
	["428"] = {["name"] = "Direct-Debiting-Failure-Handle", ["type"] = "Enum", ["Range"] = {
		[0] = "TERMINATE_OR_BUFFER",
		[1] = "CONTINUE"
	}},
	["456"] = {["name"] = "Multiple-Service-Credit-Control", ["type"] = "Group"},
	["871"] = {["name"] = "Quota-Holding-Time", ["type"] = "Uint32"},
	["881"] = {["name"] = "Quota-Consumption-Time", ["type"] = "Uint32"},
	["448"] = {["name"] = "Validity-Time", ["type"] = "Uint32"},
	["438"] = {["name"] = "Restriction-Filter-Rule", ["type"] = "String"},
	["11"] = {["name"] = "Filter-Id", ["type"] = "Group"},
	["279"] = {["name"] = "Failed-AVP", ["type"] = "Group"},
	["20372"] = {["name"] = "Account-Type", ["type"] = "Uint32"},
	["20330"] = {["name"] = "AoC-Balance", ["type"] = "Uint32"},
	["20331"] = {["name"] = "AoC-Language-ID", ["type"] = "Enum", ["Range"] = {
		[0] = "Mix", [1] = "Chinese", [2] = "English", [3] = "Local Language"
	}},
	["20332"] = {["name"] = "AoC-Tariff", ["type"] = "Group"},
	["20333"] = {["name"] = "AoC-Start-Time", ["type"] = "Uint32"},
	["20334"] = {["name"] = "AoC-Unit", ["type"] = "Uint32"},
	["20335"] = {["name"] = "AoC-Price", ["type"] = "Uint32"},
	["20356"] = {["name"] = "Account-Information", ["type"] = "Group"},
	["20357"] = {["name"] = "AccountId", ["type"] = "String"},
	["20359"] = {["name"] = "AccountDate", ["type"] = "Uint32"},
	["20631"] = {["name"] = "Service-Result-Code", ["type"] = "Uint32"},
	["50104"] = {["name"] = "Total-Balance-Available", ["type"] = "Uint32"},
	["20521"] = {["name"] = "Result-Code-Desc", ["type"] = "String"},
	["257"] = {["name"] = "Balance-Reserved", ["type"] = "Uint64"},
	["80074"] = {["name"] = "Business-Security-Information", ["type"] = "Group"},
	["80075"] = {["name"] = "Business-Security-Data", ["type"] = "String"},
	["80076"] = {["name"] = "Key-Version", ["type"] = "String"},
	["259"] = {["name"] = "Acct-Application-Id", ["type"] = "Uint32"},
	["269"] = {["name"] = "Product-Name", ["type"] = "String"},
	["266"] = {["name"] = "Vendor-Id", ["type"] = "Uint32"},
	["265"] = {["name"] = "Supported-Vendor-Id", ["type"] = "Uint32"},
	["260"] = {["name"] = "Vendor-Specific-Application-Id", ["type"] = "Group"},
	["267"] = {["name"] = "Firmware-Revision", ["type"] = "Uint32"},
};


local CMD_DEF = {
	[272] = {[0] = "CCA", [1] = "CCR"},
	[258] = {[0] = "RAA", [1] = "RAR"},
	[274] = {[0] = "ASA", [1] = "ASR"},
	[280] = {[0] = "DWA", [1] = "DWR"},
	[282] = {[0] = "DPA", [1] = "DPR"},
	[257] = {[0] = "CEA", [1] = "CER"}
};

function extends(ParentKlass) 
	local klass = {};
	setmetatable(klass, ParentKlass);
	klass.__index = klass;
	return klass;
end

local function getByteBits(n)
	local tn = n;
	local x = {};
	for i = 1,8 do
		x[9 - i] = (tn % 2);
		tn = math.floor(tn / 2);
	end
	return x;
end

local avp = {};

function avp.new(self) 
	local o = {};
	o._avpCode = 0;
	o._avpFlag = 0;
	o._avpLen  = 0;
	o._vendor  = "";
	o._avpData = "";
	o._avpHeadLen = 0;
	setmetatable(o, self);
	self.__index = self;
	return o;
end

function avp._parseHead(self, buf, offset) 
	self._avpCode = buf(offset,4):uint();
	offset = offset + 4;
	self._avpHeadLen = 4;

	self._avpFlag = buf(offset,1):uint();
	offset = offset + 1;
	self._avpHeadLen = self._avpHeadLen + 1;

	self._avpLen = buf(offset,3):uint();
	offset = offset + 3;
	self._avpHeadLen = self._avpHeadLen + 3;

	if self._avpFlag >= 0x80 then
		self._vendor = buf(offset,4):uint();
		offset = offset + 4;
		self._avpHeadLen = self._avpHeadLen + 4;
	end
	self._avpLen = math.floor((self._avpLen + 3)/4) * 4;
	return offset;
end

function avp.parse(self, buf, offset, curTree, blen)
	local offsetLen = {["offset"] = offset, ["blen"] = blen};
	self:_parse(buf, offsetLen, curTree);
	return offsetLen.offset;
end

function avp._align32(self, x)
	local alignLen = math.floor(((self._avpLen + 3) / 4));
	return x + (alignLen - self._avpLen);
end

function avp._printAVP(self, buf, off, curTree)
	local at = curTree:add(ocp_proto, buf(off, self._avpLen), "[Unknown AVP]");
	local fb = getByteBits(self._avpFlag);
	local sflag = {[8] = "r", [7] = "r", [6] = "r", [5] = "r",
				   [4] = "r", [3] = "P", [2] = "M", [1] = "V"};
	for i=8,1,-1 do
		sflag[i] = sflag[i] .. "(" .. fb[i] .. ")";
	end
	local af = table.concat(sflag, ",");
	at:add(ocp_proto.fields.avpCode, buf(off, 4));
	at:add(ocp_proto.fields.avpFlag, buf(off+4,1));
	at:add(ocp_proto.fields.strFlag, af);
	at:add(ocp_proto.fields.avpLen, buf(off+5, 3));
	if self._avpHeadLen > 8 then
		at:add(ocp_proto.fields.avpVendor, buf(off+8,4));
		at:add(ocp_proto.fields.avpData, buf(off+12, self._avpLen - 12));
	else
		at:add(ocp_proto.fields.avpData, buf(off+8, self._avpLen - 8));
	end
end

function avp._parse(self, buf, ol, curTree)
	if ol.offset >= ol.blen then
		return;
	end
	local off0 = ol.offset;
	ol.offset = self:_parseHead(buf, ol.offset);
	-- curTree:add(ocp_proto.fields.debug, "avpLen: " .. self._avpLen .. ", avp head len: " .. self._avpHeadLen);
	local bodyLen = self._avpLen - self._avpHeadLen;
	if bodyLen + ol.offset > ol.blen then
		bodyLen = ol.blen - ol.offset;
	end
	local ai = AVP_DEF["" .. self._avpCode];
	if ai == nil then
		self:_printAVP(buf, off0, curTree);
		ol.offset = off0 + self._avpLen;
		return;
	end
	local field = nil;
	if ai["type"] == "Group" then
		-- curTree:add(ocp_proto.fields.debug, "parse group");
		local mt = curTree:add(ocp_proto, buf(ol.offset, bodyLen), "[" .. ai["name"] .. "]");
		local tmpIndex = {["offset"] = ol.offset, ["blen"] = bodyLen + ol.offset};
		while true do
			-- local _ta = avp:new();
			local _ta = avp:new();
			_ta:_parse(buf, tmpIndex, mt);
			if tmpIndex.offset >= tmpIndex.blen then
				break;
			end
		end
	else
		field = ocp_proto.fields["" .. self._avpCode];
		if field ~= nil then
			-- curTree:add(ocp_proto.fields.debug, "bodyLen: " .. bodyLen .. ", offset:" .. ol.offset);
			curTree:add(field, buf(ol.offset, bodyLen));
		else
			self:_printAVP(buf, off0, curTree);
		end
	end
	-- ol.offset = off0 + self._avpLen + 1;
	ol.offset = off0 + self._avpLen;
end

local OcpHead = {
	new = function(self)
		local o = {};
		o.msgLen  = 0;
		o._cmdFlag = 0;
		o._cmdCode = 0;
		o.cmdName = "";
		setmetatable(o, self);
		self.__index = self;
		return o;
	end,

	parse = function(self, buf, off, blen, root)
		if blen < 20 then
			return off;
		end
		off = off + 1;

		self.msgLen = buf(off, 3):uint();
		local curTree = root:add(ocp_proto, buf(off-1, 20),  "[OCP-HEADER]");
		curTree:add(ocp_proto.fields.ocp_version, buf(off-1, 1));
		curTree:add(ocp_proto.fields.ocp_msgLen, buf(off, 3));
		off = off + 3;

		self._cmdFlag = buf(off, 1):uint();
		local cmdStrFlag = "" .. self._cmdFlag .. ": ";
		local tmpflag = getByteBits(self._cmdFlag);
		local tbflag = {[8] = "r", [7] = "r", [6] = "r", [5] = "r", 
						[4] = "T", [3] = "E", [2] = "P", [1] = "R"};
		for i = 8,1,-1 do
			tbflag[i] = tbflag[i] .. "(" .. tmpflag[i] .. ")";
		end
		local cmdStrFlag = cmdStrFlag .. table.concat(tbflag, ",");
		curTree:add(ocp_proto.fields.ocp_cmdFlag, buf(off, 1));
		curTree:add(ocp_proto.fields.strFlag, cmdStrFlag);
		off = off + 1;

		self._cmdCode = buf(off, 3):uint();
		if CMD_DEF[self._cmdCode] ~= nil then
			self.cmdName = CMD_DEF[self._cmdCode][tmpflag[1]];
		else
			self.cmdName = "" .. self._cmdCode;
		end
		curTree:add(ocp_proto.fields.ocp_cmdCode, buf(off, 3));
		off = off + 3;

		curTree:add(ocp_proto.fields.ocp_appId, buf(off, 4));
		off = off + 4;

		curTree:add(ocp_proto.fields.ocp_hbh, buf(off, 4));
		off = off + 4;

		curTree:add(ocp_proto.fields.ocp_e2e, buf(off, 4));
		off = off + 4;
		local reqtype = 0;
		if self._cmdFlag >= 0x80 then
			reqtype = 1;
		end
		return off;
	end,
};

function ocp_proto.dissector(buf, pkt, tree)
	local blen = buf:len();
	if blen == 0 then
		return;
	end
	pkt.cols.protocol = ocp_proto.name;
	local subtree = tree:add(ocp_proto, buf(0, blen));
	local offset  = 0;
	local oh = OcpHead:new();
	offset = oh:parse(buf, offset, blen, subtree); 
	if oh.cmdName ~= "" then
		pkt.cols.info = oh.cmdName;
	end
	while offset < oh.msgLen do
		local ta = avp:new();
		offset = ta:parse(buf, offset, subtree, oh.msgLen);
	end

end

-- initialization protocol
function ocp_proto.init()
end

-- register a chained dissector for ocp_port
local tcp_table = DissectorTable.get("tcp.port");
dissector = tcp_table:get_dissector(ocp_port);
tcp_table:add(ocp_port, ocp_proto);


-- init coloumns
ocp_proto.fields.debug = ProtoField.string("DEBUG", "DEBUG");
ocp_proto.fields.strFlag  = ProtoField.string("FlagInfo", "Flag Info");
ocp_proto.fields.unknown = ProtoField.string("AVP", "AVP");
ocp_proto.fields.avpCode = ProtoField.uint32("AVPCode", "AVP Code");
ocp_proto.fields.avpFlag = ProtoField.uint8("AVPFlag", "AVP Flag");
ocp_proto.fields.avpLen = ProtoField.uint32("AVPLength", "AVP Length");
ocp_proto.fields.avpVendor = ProtoField.uint32("AVPVendor", "AVP Vendor");
ocp_proto.fields.avpData = ProtoField.string("AVPData", "AVP Data");
for k, v in pairs(AVP_DEF) do
	local field = nil;
	local n = v["name"];
	if v["name"] == nil then
		n = "unknow";
	end
	if v["type"] == "String" or v["type"] == "UTF8String" then
		field = ProtoField.string(n, n);
	elseif v["type"] == "Int32" or v["type"] == "Uint32" then
		field = ProtoField.uint32(n, n, base.DEC);
	elseif v["type"] == "Int64" or v["type"] == "Uint64" then
		field = ProtoField.uint64(n, n, base.DEC);
	elseif v["type"] == "Enum" then
		field = ProtoField.uint32(n, n, base.DEC, v["Range"]);
	end
	if field ~= nil then
		ocp_proto.fields[k] = field;
	end
end
ocp_proto.fields.ocp_version = ProtoField.uint8("Version", "Version", base.DEC);

ocp_proto.fields.ocp_msgLen = ProtoField.uint32("MsgLen", "Message length", base.DEC);
ocp_proto.fields.ocp_cmdFlag = ProtoField.uint8("CmdFlags", "Command Flags", base.DEC);
ocp_proto.fields.ocp_cmdCode = ProtoField.uint32("CmdCode", "Command Code", base.DEC);
ocp_proto.fields.ocp_appId = ProtoField.uint32("Application-ID", "Application ID", base.DEC);
ocp_proto.fields.ocp_hbh = ProtoField.uint32("Hop-by-Hop", "Hop by Hop", base.DEC);
ocp_proto.fields.ocp_e2e = ProtoField.uint32("End-to-End", "End to End", base.DEC);
