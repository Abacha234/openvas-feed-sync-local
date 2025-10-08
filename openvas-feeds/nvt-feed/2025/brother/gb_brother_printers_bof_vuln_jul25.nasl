# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171724");
  script_version("2025-10-07T05:38:31+0000");
  script_tag(name:"last_modification", value:"2025-10-07 05:38:31 +0000 (Tue, 07 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-01 08:54:56 +0000 (Wed, 01 Oct 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-20 00:29:00 +0000 (Thu, 20 Jul 2017)");

  script_cve_id("CVE-2017-9765");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Brother Printers Buffer Overflow Vulnerability (Jul 2025)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_brother_printer_consolidation.nasl");
  script_mandatory_keys("brother/printer/detected");

  script_tag(name:"summary", value:"Multiple Brother printers are prone to a buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"insight", value:"Integer overflow in the soap_get function in Genivia gSOAP
  allows remote attackers to execute arbitrary code or cause a denial of service (stack-based
  buffer overflow and application crash) via a large XML document, aka Devil's Ivy.

  NOTE: the large document would be blocked by many common web-server configurations on
  general-purpose computers.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.brother.com/g/b/faqend.aspx?c=us&lang=en&prod=group2&faqid=faq00100846_000");
  script_xref(name:"URL", value:"https://support.brother.com/g/s/id/security/CVE-2017-9765.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:brother:dcp-j1100dw_firmware",
                     "cpe:/o:brother:dcp-j572dw_firmware",
                     "cpe:/o:brother:mfc-j1300dw_firmware",
                     "cpe:/o:brother:mfc-j1500n_firmware",
                     "cpe:/o:brother:mfc-j995dw_firmware",
                     "cpe:/o:brother:mfc-j995dwxl_firmware",
                     "cpe:/o:brother:fax-l2710dn_firmware",
                     "cpe:/o:brother:mfc-7880dn_firmware",
                     "cpe:/o:brother:mfc-7889dw_firmware",
                     "cpe:/o:brother:mfc-l2730dn_firmware",
                     "cpe:/o:brother:dcp-j572n_firmware",
                     "cpe:/o:brother:dcp-j577n_firmware",
                     "cpe:/o:brother:dcp-j582n_firmware",
                     "cpe:/o:brother:mfc-j2330dw_firmware",
                     "cpe:/o:brother:mfc-j3530dw_firmware",
                     "cpe:/o:brother:mfc-j5330dw_firmware",
                     "cpe:/o:brother:mfc-j5335dw_firmware",
                     "cpe:/o:brother:mfc-j6530dw_firmware",
                     "cpe:/o:brother:mfc-j6730dw_firmware",
                     "cpe:/o:brother:dcp-l2540dn_firmware",
                     "cpe:/o:brother:dcp-l2540dnr_firmware",
                     "cpe:/o:brother:dcp-l2540dw_firmware",
                     "cpe:/o:brother:dcp-l2541dw_firmware",
                     "cpe:/o:brother:mfc-l2680w_firmware",
                     "cpe:/o:brother:mfc-l2685dw_firmware",
                     "cpe:/o:brother:mfc-l2700dn_firmware",
                     "cpe:/o:brother:mfc-l2700dw_firmware",
                     "cpe:/o:brother:mfc-l2700dwr_firmware",
                     "cpe:/o:brother:mfc-l2720dw_firmware",
                     "cpe:/o:brother:mfc-l2720dwr_firmware",
                     "cpe:/o:brother:dcp-j772dw_firmware",
                     "cpe:/o:brother:dcp-j774dw_firmware",
                     "cpe:/o:brother:mfc-j690dw_firmware",
                     "cpe:/o:brother:mfc-j6945dw_firmware",
                     "cpe:/o:brother:mfc-j6947dw_firmware",
                     "cpe:/o:brother:mfc-j6997cdw_firmware",
                     "cpe:/o:brother:mfc-j6999cdw_firmware",
                     "cpe:/o:brother:mfc-j890dw_firmware",
                     "cpe:/o:brother:mfc-j895dw_firmware",
                     "cpe:/o:brother:dcp-j972n_firmware",
                     "cpe:/o:brother:dcp-j973n-w_firmware",
                     "cpe:/o:brother:dcp-j973n-b_firmware",
                     "cpe:/o:brother:dcp-j978n-w_firmware",
                     "cpe:/o:brother:dcp-j978n-b_firmware",
                     "cpe:/o:brother:dcp-j981n_firmware",
                     "cpe:/o:brother:dcp-j982n-w_firmware",
                     "cpe:/o:brother:dcp-j982n-b_firmware",
                     "cpe:/o:brother:mfc-j2730dw_firmware",
                     "cpe:/o:brother:mfc-j5730dw_firmware",
                     "cpe:/o:brother:mfc-j5830dw_firmware",
                     "cpe:/o:brother:mfc-j5930dw_firmware",
                     "cpe:/o:brother:dcp-1610w_firmware",
                     "cpe:/o:brother:dcp-1610we_firmware",
                     "cpe:/o:brother:dcp-1610wr_firmware",
                     "cpe:/o:brother:dcp-1612w_firmware",
                     "cpe:/o:brother:dcp-1612we_firmware",
                     "cpe:/o:brother:dcp-1612wr_firmware",
                     "cpe:/o:brother:dcp-1622we_firmware",
                     "cpe:/o:brother:dcp-1623we_firmware",
                     "cpe:/o:brother:dcp-1623wr_firmware",
                     "cpe:/o:brother:dcp-j987n-w_firmware",
                     "cpe:/o:brother:dcp-j987n-b_firmware",
                     "cpe:/o:brother:dcp-j988n_firmware",
                     "cpe:/o:brother:dcp-t510w_firmware",
                     "cpe:/o:brother:dcp-t710w_firmware",
                     "cpe:/o:brother:mfc-j491dw_firmware",
                     "cpe:/o:brother:mfc-j497dw_firmware",
                     "cpe:/o:brother:mfc-t810w_firmware",
                     "cpe:/o:brother:mfc-t910dw_firmware",
                     "cpe:/o:brother:dcp-1615nw_firmware",
                     "cpe:/o:brother:dcp-1616nw_firmware",
                     "cpe:/o:brother:dcp-1617nw_firmware",
                     "cpe:/o:brother:fax-l2700dn_firmware",
                     "cpe:/o:brother:hl-j6000cdw_firmware",
                     "cpe:/o:brother:hl-j6000dw_firmware",
                     "cpe:/o:brother:hl-j6100dw_firmware",
                     "cpe:/o:brother:mfc-j5945dw_firmware",
                     "cpe:/o:brother:mfc-j6980cdw_firmware",
                     "cpe:/o:brother:mfc-j6995cdw_firmware",
                     "cpe:/o:brother:dcp-7190dn_firmware",
                     "cpe:/o:brother:dcp-b7530dn_firmware",
                     "cpe:/o:brother:mfc-1910w_firmware",
                     "cpe:/o:brother:mfc-1910we_firmware",
                     "cpe:/o:brother:mfc-1911nw_firmware",
                     "cpe:/o:brother:mfc-1911w_firmware",
                     "cpe:/o:brother:mfc-1912wr_firmware",
                     "cpe:/o:brother:mfc-1915w_firmware",
                     "cpe:/o:brother:mfc-1916nw_firmware",
                     "cpe:/o:brother:mfc-7890dn_firmware",
                     "cpe:/o:brother:mfc-b7720dn_firmware",
                     "cpe:/o:brother:mfc-l2720dn_firmware",
                     "cpe:/o:brother:hl-t4000dw_firmware",
                     "cpe:/o:brother:mfc-j5630cdw_firmware",
                     "cpe:/o:brother:mfc-j1605dn_firmware",
                     "cpe:/o:brother:mfc-j6583cdw_firmware",
                     "cpe:/o:brother:mfc-j6983cdw_firmware",
                     "cpe:/o:brother:mfc-j3930dw_firmware",
                     "cpe:/o:brother:mfc-j6535dw_firmware",
                     "cpe:/o:brother:mfc-j6930dw_firmware",
                     "cpe:/o:brother:mfc-j6935dw_firmware",
                     "cpe:/o:brother:dcp-l3510cdw_firmware",
                     "cpe:/o:brother:dcp-l3517cdw_firmware",
                     "cpe:/o:brother:dcp-l3551cdw_firmware",
                     "cpe:/o:brother:hl-l3290cdw_firmware",
                     "cpe:/o:brother:mfc-j5845dw_firmware",
                     "cpe:/o:brother:mfc-j5845dwxl_firmware",
                     "cpe:/o:brother:dcp-1618w_firmware",
                     "cpe:/o:brother:dcp-7180dn_firmware",
                     "cpe:/o:brother:dcp-7189dw_firmware",
                     "cpe:/o:brother:dcp-7195dw_firmware",
                     "cpe:/o:brother:mfc-1919nw_firmware",
                     "cpe:/o:brother:mfc-7895dw_firmware",
                     "cpe:/o:brother:mfc-j6580cdw_firmware",
                     "cpe:/o:brother:mfc-j738dn_firmware",
                     "cpe:/o:brother:mfc-j738dwn_firmware",
                     "cpe:/o:brother:mfc-j998dn_firmware",
                     "cpe:/o:brother:mfc-j998dwn_firmware",
                     "cpe:/o:brother:mfc-t4500dw_firmware",
                     "cpe:/o:brother:mfc-j805dw_firmware",
                     "cpe:/o:brother:mfc-j805dwxl_firmware",
                     "cpe:/o:brother:mfc-j815dwxl_firmware",
                     "cpe:/o:brother:dcp-7090dw_firmware",
                     "cpe:/o:brother:dcp-7190dw_firmware",
                     "cpe:/o:brother:mfc-j893n_firmware",
                     "cpe:/o:brother:mfc-j898n_firmware",
                     "cpe:/o:brother:nfc-j903n_firmware",
                     "cpe:/o:brother:dcp-9030cdn_firmware",
                     "cpe:/o:brother:dcp-l3550cdw_firmware",
                     "cpe:/o:brother:mfc-9150cdn_firmware",
                     "cpe:/o:brother:mfc-9350cdw_firmware",
                     "cpe:/o:brother:mfc-l3710cdw_firmware",
                     "cpe:/o:brother:mfc-l3730cdn_firmware",
                     "cpe:/o:brother:mfc-l3735cdn_firmware",
                     "cpe:/o:brother:mfc-l3745cdw_firmware",
                     "cpe:/o:brother:mfc-l3750cdw_firmware",
                     "cpe:/o:brother:mfc-l3770cdw_firmware",
                     "cpe:/o:brother:dcp-b7520dw_firmware",
                     "cpe:/o:brother:dcp-b7535dw_firmware",
                     "cpe:/o:brother:dcp-l2530dw_firmware",
                     "cpe:/o:brother:dcp-l2530dwr_firmware",
                     "cpe:/o:brother:dcp-l2531dw_firmware",
                     "cpe:/o:brother:dcp-l2532dw_firmware",
                     "cpe:/o:brother:dcp-l2535dw_firmware",
                     "cpe:/o:brother:dcp-l2537dw_firmware",
                     "cpe:/o:brother:dcp-l2550dn_firmware",
                     "cpe:/o:brother:dcp-l2550dnr_firmware",
                     "cpe:/o:brother:dcp-l2550dw_firmware",
                     "cpe:/o:brother:dcp-l2551dn_firmware",
                     "cpe:/o:brother:dcp-l2551dw_firmware",
                     "cpe:/o:brother:dcp-l2552dn_firmware",
                     "cpe:/o:brother:hl-l2390dw_firmware",
                     "cpe:/o:brother:hl-l2395dw_firmware",
                     "cpe:/o:brother:mfc-b7715dw_firmware",
                     "cpe:/o:brother:mfc-l2690dw_firmware",
                     "cpe:/o:brother:mfc-l2710dn_firmware",
                     "cpe:/o:brother:mfc-l2710dnr_firmware",
                     "cpe:/o:brother:mfc-l2710dw_firmware",
                     "cpe:/o:brother:mfc-l2710dwr_firmware",
                     "cpe:/o:brother:mfc-l2712dn_firmware",
                     "cpe:/o:brother:mfc-l2712dw_firmware",
                     "cpe:/o:brother:mfc-l2713dw_firmware",
                     "cpe:/o:brother:mfc-l2715dw_firmware",
                     "cpe:/o:brother:mfc-l2716dw_firmware",
                     "cpe:/o:brother:mfc-l2717dw_firmware",
                     "cpe:/o:brother:mfc-l2730dw_firmware",
                     "cpe:/o:brother:mfc-l2730dwr_firmware",
                     "cpe:/o:brother:mfc-l2732dw_firmware",
                     "cpe:/o:brother:mfc-l2750dw_firmware",
                     "cpe:/o:brother:mfc-l2750dwr_firmware",
                     "cpe:/o:brother:mfc-l2750dwxl_firmware",
                     "cpe:/o:brother:mfc-l2751dw_firmware",
                     "cpe:/o:brother:mfc-l2770dw_firmware",
                     "cpe:/o:brother:mfc-l2771dw_firmware",
                     "cpe:/o:brother:mfc-l8900cdw_firmware",
                     "cpe:/o:brother:mfc-l9570cdw_firmware",
                     "cpe:/o:brother:mfc-l9577cdw_firmware",
                     "cpe:/o:brother:dcp-l2520dw_firmware",
                     "cpe:/o:brother:dcp-l2520dwr_firmware",
                     "cpe:/o:brother:mfc-l2740dw_firmware",
                     "cpe:/o:brother:mfc-l2740dwr_firmware",
                     "cpe:/o:brother:dcp-l2560dw_firmware",
                     "cpe:/o:brother:dcp-l2560dwr_firmware",
                     "cpe:/o:brother:hl-l2380dw_firmware",
                     "cpe:/o:brother:mfc-l2701dw_firmware",
                     "cpe:/o:brother:mfc-l2703dw_firmware",
                     "cpe:/o:brother:mfc-l2705dw_firmware",
                     "cpe:/o:brother:mfc-l2707dw_firmware",
                     "cpe:/o:brother:mfc-l6900dwg_firmware",
                     "cpe:/o:brother:dcp-l5500dn_firmware",
                     "cpe:/o:brother:dcp-l5502dn_firmware",
                     "cpe:/o:brother:dcp-l5600dn_firmware",
                     "cpe:/o:brother:dcp-l5602dn_firmware",
                     "cpe:/o:brother:dcp-l5650dn_firmware",
                     "cpe:/o:brother:dcp-l5652dn_firmware",
                     "cpe:/o:brother:dcp-l6600dw_firmware",
                     "cpe:/o:brother:mfc-8530dn_firmware",
                     "cpe:/o:brother:mfc-8540dn_firmware",
                     "cpe:/o:brother:mfc-l5700dn_firmware",
                     "cpe:/o:brother:mfc-l5700dw_firmware",
                     "cpe:/o:brother:mfc-l5702dw_firmware",
                     "cpe:/o:brother:mfc-l5750dw_firmware",
                     "cpe:/o:brother:mfc-l5755dw_firmware",
                     "cpe:/o:brother:mfc-l5800dw_firmware",
                     "cpe:/o:brother:mfc-l5802dw_firmware",
                     "cpe:/o:brother:mfc-l5850dw_firmware",
                     "cpe:/o:brother:mfc-l5900dw_firmware",
                     "cpe:/o:brother:mfc-l5902dw_firmware",
                     "cpe:/o:brother:mfc-l6700dw_firmware",
                     "cpe:/o:brother:mfc-l6702dw_firmware",
                     "cpe:/o:brother:mfc-l6750dw_firmware",
                     "cpe:/o:brother:mfc-l6800dw_firmware",
                     "cpe:/o:brother:mfc-l6900dw_firmware",
                     "cpe:/o:brother:mfc-l6902dw_firmware",
                     "cpe:/o:brother:mfc-l6950dw_firmware",
                     "cpe:/o:brother:mfc-l6970dw_firmware",
                     "cpe:/o:brother:dcp-l8410cdw_firmware",
                     "cpe:/o:brother:mfc-l8610cdw_firmware",
                     "cpe:/o:brother:mfc-l8690cdw_firmware",
                     "cpe:/o:brother:hl-1210w_firmware",
                     "cpe:/o:brother:hl-1210we_firmware",
                     "cpe:/o:brother:hl-1210wr_firmware",
                     "cpe:/o:brother:hl-1211w_firmware",
                     "cpe:/o:brother:hl-1212w_firmware",
                     "cpe:/o:brother:hl-1212we_firmware",
                     "cpe:/o:brother:hl-1212wr_firmware",
                     "cpe:/o:brother:hl-1218w_firmware",
                     "cpe:/o:brother:hl-1222we_firmware",
                     "cpe:/o:brother:hl-1223we_firmware",
                     "cpe:/o:brother:hl-1223wr_firmware",
                     "cpe:/o:brother:hl-2560dn_firmware",
                     "cpe:/o:brother:hl-2569dw_firmware",
                     "cpe:/o:brother:hl-3190cdw_firmware",
                     "cpe:/o:brother:hl-l2360dn_firmware",
                     "cpe:/o:brother:hl-l2360dnr_firmware",
                     "cpe:/o:brother:hl-l2360dw_firmware",
                     "cpe:/o:brother:hl-l2361dn_firmware",
                     "cpe:/o:brother:hl-l2365dw_firmware",
                     "cpe:/o:brother:hl-l2365dwr_firmware",
                     "cpe:/o:brother:hl-l2366dw_firmware",
                     "cpe:/o:brother:hl-l3270cdw_firmware",
                     "cpe:/o:brother:hl-2590dn_firmware",
                     "cpe:/o:brother:hl-2595dw_firmware",
                     "cpe:/o:brother:hl-b2050dn_firmware",
                     "cpe:/o:brother:hl-b2080dw_firmware",
                     "cpe:/o:brother:hl-l2325dw_firmware",
                     "cpe:/o:brother:hl-l2350dw_firmware",
                     "cpe:/o:brother:hl-l2350dwr_firmware",
                     "cpe:/o:brother:hl-l2351dw_firmware",
                     "cpe:/o:brother:hl-l2352dw_firmware",
                     "cpe:/o:brother:hl-l2357dw_firmware",
                     "cpe:/o:brother:hl-l2370dn_firmware",
                     "cpe:/o:brother:hl-l2370dnr_firmware",
                     "cpe:/o:brother:hl-l2370dw_firmware",
                     "cpe:/o:brother:hl-l2370dwxl_firmware",
                     "cpe:/o:brother:hl-l2371dn_firmware",
                     "cpe:/o:brother:hl-l2372dn_firmware",
                     "cpe:/o:brother:hl-l2375dw_firmware",
                     "cpe:/o:brother:hl-l2375dwr_firmware",
                     "cpe:/o:brother:hl-l2376dw_firmware",
                     "cpe:/o:brother:hl-l2385dw_firmware",
                     "cpe:/o:brother:hl-l2386dw_firmware",
                     "cpe:/o:brother:hl-3160cdw_firmware",
                     "cpe:/o:brother:hl-l3210cw_firmware",
                     "cpe:/o:brother:hl-l3230cdn_firmware",
                     "cpe:/o:brother:hl-l3230cdw_firmware",
                     "cpe:/o:brother:hl-5590dn_firmware",
                     "cpe:/o:brother:hl-5595dn_firmware",
                     "cpe:/o:brother:hl-5595dnh_firmware",
                     "cpe:/o:brother:hl-l5050dn_firmware",
                     "cpe:/o:brother:hl-l5100dn_firmware",
                     "cpe:/o:brother:hl-l5100dnt_firmware",
                     "cpe:/o:brother:hl-l5102dw_firmware",
                     "cpe:/o:brother:hl-l5200dw_firmware",
                     "cpe:/o:brother:hl-l5200dwt_firmware",
                     "cpe:/o:brother:hl-l5202dw_firmware",
                     "cpe:/o:brother:hl-l6200dw_firmware",
                     "cpe:/o:brother:hl-l6200dwt_firmware",
                     "cpe:/o:brother:hl-l6202dw_firmware",
                     "cpe:/o:brother:hl-l6250dn_firmware",
                     "cpe:/o:brother:hl-l6250dw_firmware",
                     "cpe:/o:brother:hl-l2305w_firmware",
                     "cpe:/o:brother:hl-l2315dw_firmware",
                     "cpe:/o:brother:hl-l2340dw_firmware",
                     "cpe:/o:brother:hl-l2340dwr_firmware",
                     "cpe:/o:brother:hl-l6300dw_firmware",
                     "cpe:/o:brother:hl-l6300dwt_firmware",
                     "cpe:/o:brother:hl-l6400dw_firmware",
                     "cpe:/o:brother:hl-l6400dwt_firmware",
                     "cpe:/o:brother:hl-l6402dw_firmware",
                     "cpe:/o:brother:hl-l6450dw_firmware",
                     "cpe:/o:brother:hl-l6400dwg_firmware",
                     "cpe:/o:brother:hl-l8260cdn_firmware",
                     "cpe:/o:brother:hl-l8260cdw_firmware",
                     "cpe:/o:brother:hl-l8360cdw_firmware",
                     "cpe:/o:brother:hl-l8360cdwt_firmware",
                     "cpe:/o:brother:hl-l9310cdw_firmware");



if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

version = infos["version"];
cpe = infos["cpe"];

if (cpe == "cpe:/o:brother:dcp-j1100dw_firmware" ||
    cpe == "cpe:/o:brother:dcp-j572dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-j1300dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-j1500n_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-j995(dw|dwxl)_firmware" ||
    cpe == "cpe:/o:brother:fax-l2710dn_firmware" ||
    cpe == "cpe:/o:brother:mfc-7880dn_firmware" ||
    cpe == "cpe:/o:brother:mfc-7889dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-l2730dn_firmware") {
  if (version_is_less(version: version, test_version: "p")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "P");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-j5(72|77|82)n_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-j(23|35|53|65|67)30dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-j5335dw_firmware" ||
    cpe =~ "^cpe:/o:brother:dcp-l2540(dn|dnr|dw)_firmware" ||
    cpe == "cpe:/o:brother:dcp-l2541dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l268(0w|5dw)_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l27[02]0(dw|dwr)_firmware" ||
    cpe == "cpe:/o:brother:mfc-l2700dn_firmware") {
  if (version_is_less(version: version, test_version: "w")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "W");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-j77[24]dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-j69(0dw|45dw|47dw)_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-j699[79]cdw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-j89[05]dw_firmware") {
  if (version_is_less(version: version, test_version: "t")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "T");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-j9(72|81)n_firmware" ||
    cpe =~ "^cpe:/o:brother:dcp-j9(73|78|82)n-(w|b)_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-j(27|57|58|59)30dw_firmware" ||
    cpe =~ "^cpe:/o:brother:dcp-161[02](w|we|wr)_firmware" ||
    cpe =~ "^cpe:/o:brother:dcp-162[23]we_firmware" ||
    cpe == "cpe:/o:brother:dcp-1623wr_firmware") {
  if (version_is_less(version: version, test_version: "y")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "Y");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-j987n-(w|b)_firmware") {
  if (version_is_less(version: version, test_version: "f")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "F");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:dcp-j988n_firmware" ||
    cpe =~ "^cpe:/o:brother:dcp-t[57]10w_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-j49[17]dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-t810w_firmware" ||
    cpe == "cpe:/o:brother:mfc-t910dw_firmware" ||
    cpe =~ "^cpe:/o:brother:dcp-161[567]nw_firmware" ||
    cpe == "cpe:/o:brother:fax-l2700dn_firmware") {
  if (version_is_less(version: version, test_version: "q")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "Q");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:hl-j6000cdw_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-j6[01]00dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-j5945dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-j69(80|95)cdw_firmware" ||
    cpe == "cpe:/o:brother:dcp-7190dn_firmware" ||
    cpe == "cpe:/o:brother:dcp-b7530dn_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-191[015]w_firmware" ||
    cpe == "cpe:/o:brother:mfc-1910we_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-191[16]nw_firmware" ||
    cpe == "cpe:/o:brother:mfc-1912wr_firmware" ||
    cpe == "cpe:/o:brother:mfc-7890dn_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-(b7|l2)720dn_firmware") {
  if (version_is_less(version: version, test_version: "s")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "S");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:hl-t4000dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-j5630cdw_firmware") {
  if (version_is_less(version: version, test_version: "l")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "L");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j[36]930dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-j6[59]35dw_firmware" ||
    cpe =~ "^cpe:/o:brother:dcp-l35(10|17|51)cdw_firmware" ||
    cpe == "cpe:/o:brother:hl-l3290cdw_firmware") {
  if (version_is_less(version: version, test_version: "z")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "Z");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j5845dw(|xl)_firmware" ||
    cpe == "cpe:/o:brother:dcp-1618w_firmware" ||
    cpe == "cpe:/o:brother:dcp-7180dn_firmware" ||
    cpe =~ "^cpe:/o:brother:dcp-71(89|95)dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-1919nw_firmware" ||
    cpe == "cpe:/o:brother:mfc-7895dw_firmware") {
  if (version_is_less(version: version, test_version: "n")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "N");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j6580cdw_firmware") {
  if (version_is_less(version: version, test_version: "r")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "R");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j(73|99)8(dn|dwn)_firmware" ||
    cpe == "cpe:/o:brother:mfc-t4500dw_firmware") {
  if (version_is_less(version: version, test_version: "m")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "M");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j805dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-j8[01]5dwxl_firmware" ||
    cpe =~ "^cpe:/o:brother:dcp-7[01]90dw_firmware") {
  if (version_is_less(version: version, test_version: "j")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "J");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:nfc-j903n_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-j89[38]n_firmware") {
  if (version_is_less(version: version, test_version: "j")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "J");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "cpe:/o:brother:nfc-j903n_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-j89[38]n_firmware") {
  if (version_is_less(version: version, test_version: "zb")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "ZB");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:dcp-9030cdn_firmware" ||
    cpe == "cpe:/o:brother:dcp-l3550cdw_firmware" ||
    cpe == "cpe:/o:brother:mfc-9150cdn_firmware" ||
    cpe == "cpe:/o:brother:mfc-9350cdw_firmware" ||
    cpe == "cpe:/o:brother:mfc-l3710cdw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l373[05]cdn_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l37(45|50|70)cdw_firmware") {
  if (version_is_less(version: version, test_version: "zb")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "ZB");
    security_message(port: 0, data: report);
    exit(0);
  }
}
if (cpe =~ "^cpe:/o:brother:dcp-b75(20|35)dw_firmware" ||
    cpe =~ "^cpe:/o:brother:dcp-l253[01257]dw_firmware" ||
    cpe == "cpe:/o:brother:dcp-l2530dwr_firmware" ||
    cpe =~ "^cpe:/o:brother:dcp-l255[012]dn_firmware" ||
    cpe == "cpe:/o:brother:dcp-l2550dnr_firmware" ||
    cpe =~ "^cpe:/o:brother:dcp-l255[01]dw_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l239[05]dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-b7715dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-l2690dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l2710(dn|dnr|dw|dwr)_firmware" ||
    cpe == "cpe:/o:brother:mfc-l2712dn_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l271[23567]dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l27(30|32|50)dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l27[35]0dwr_firmware" ||
    cpe == "cpe:/o:brother:mfc-l2750dwxl_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l27(51|70|71)dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-l8900cdw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l957[07]cdw_firmware") {
  if (version_is_less(version: version, test_version: "za")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "ZA");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-l2520(dw|dwr)_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l2740(dw|dwr)_firmware") {
  if (version_is_less(version: version, test_version: "v")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "V");
    security_message(port: 0, data: report);
    exit(0);
  }
}
if (cpe =~ "^cpe:/o:brother:dcp-l2560(dw|dwr)_firmware" ||
    cpe == "cpe:/o:brother:hl-l2380dw_firmware" ||
    cpe =~ "cpe:/o:brother:mfc-l270[1357]dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-l6900dwg_firmware") {
  if (version_is_less(version: version, test_version: "u")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "U");
    security_message(port: 0, data: report);
    exit(0);
  }
}
if (cpe =~ "^cpe:/o:brother:dcp-l5[56]0[02]dn_firmware" ||
    cpe =~ "^cpe:/o:brother:dcp-l565[02]dn_firmware" ||
    cpe == "cpe:/o:brother:dcp-l6600dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-85[34]0dn_firmware" ||
    cpe == "cpe:/o:brother:mfc-l5700dn_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l5[789]0[02]dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l5[78]50dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-l5755dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l6[789]00dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l6[79]02dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l6[79]50dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-l6970dw_firmware") {
  if (version_is_less(version: version, test_version: "zx")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "ZX");
    security_message(port: 0, data: report);
    exit(0);
  }
}
if (cpe == "cpe:/o:brother:dcp-l8410cdw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l86[19]0cdw_firmware") {
  if (version_is_less(version: version, test_version: "zf")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "ZF");
    security_message(port: 0, data: report);
    exit(0);
  }
}
if (cpe =~ "^cpe:/o:brother:hl-121[0128]w_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-121[02](we|wr)_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-122[23]we_firmware" ||
    cpe == "cpe:/o:brother:hl-1223wr_firmware") {
  if (version_is_less(version: version, test_version: "1.20")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.20");
    security_message(port: 0, data: report);
    exit(0);
  }
}
if (cpe == "cpe:/o:brother:hl-2560dn_firmware" ||
    cpe == "cpe:/o:brother:hl-2569dw_firmware" ||
    cpe == "cpe:/o:brother:hl-3190cdw_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l2360(dn|dnr|dw)_firmware" ||
    cpe == "cpe:/o:brother:hl-l2361dn_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l236[56]dw_firmware" ||
    cpe == "cpe:/o:brother:hl-l2365dwr_firmware" ||
    cpe == "cpe:/o:brother:hl-l3270cdw_firmware") {
  if (version_is_less(version: version, test_version: "1.34")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.34");
    security_message(port: 0, data: report);
    exit(0);
  }
}
if (cpe == "cpe:/o:brother:hl-2590dn_firmware" ||
    cpe == "cpe:/o:brother:hl-2595dw_firmware" ||
    cpe == "cpe:/o:brother:hl-b2050dn_firmware" ||
    cpe == "cpe:/o:brother:hl-b2080dw_firmware" ||
    cpe == "cpe:/o:brother:hl-l2325dw_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l235[0127]dw_firmware" ||
    cpe == "cpe:/o:brother:hl-l2350dwr_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l2370(dn|dnr|dw|dwxl)_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l237[12]dn_firmware" ||
    cpe == "cpe:/o:brother:hl-l23[78][56]dw_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l2375dwr_firmware") {
  if (version_is_less(version: version, test_version: "1.72")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.72");
    security_message(port: 0, data: report);
    exit(0);
  }
}
if (cpe == "cpe:/o:brother:hl-3160cdw_firmware" ||
    cpe == "cpe:/o:brother:hl-l3210cw_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l3230cd(n|w)_firmware") {
  if (version_is_less(version: version, test_version: "1.38")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.38");
    security_message(port: 0, data: report);
    exit(0);
  }
}
if (cpe =~ "^cpe:/o:brother:hl-559[05]dn_firmware" ||
    cpe == "cpe:/o:brother:hl-5595dnh_firmware" ||
    cpe == "cpe:/o:brother:hl-l5050dn_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l5100(dn|dnt)_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l5[12]02dw_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l[56]200(dw|dwt)_firmware" ||
    cpe == "cpe:/o:brother:hl-l6202dw_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l6250(dn|dw)_firmware") {
  if (version_is_less(version: version, test_version: "1.81")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.81");
    security_message(port: 0, data: report);
    exit(0);
  }
}
if (cpe == "cpe:/o:brother:hl-l2305w_firmware" ||
    cpe == "cpe:/o:brother:hl-l2315dw_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l2340(dw|dwr)_firmware") {
  if (version_is_less(version: version, test_version: "1.23")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.23");
    security_message(port: 0, data: report);
    exit(0);
  }
}
if (cpe =~ "^cpe:/o:brother:hl-l6[34]00(dw|dwt)_firmware" ||
    cpe == "cpe:/o:brother:hl-l6402dw_firmware" ||
    cpe == "cpe:/o:brother:hl-l6450dw_firmware") {
  if (version_is_less(version: version, test_version: "1.94")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.94");
    security_message(port: 0, data: report);
    exit(0);
  }
}
if (cpe == "cpe:/o:brother:hl-l6400dwg_firmware") {
  if (version_is_less(version: version, test_version: "1.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.4");
    security_message(port: 0, data: report);
    exit(0);
  }
}
if (cpe =~ "^cpe:/o:brother:hl-l8260cd(n|w)_firmware") {
  if (version_is_less(version: version, test_version: "1.62")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.62");
    security_message(port: 0, data: report);
    exit(0);
  }
}
if (cpe =~ "^cpe:/o:brother:hl-l8360(cdw|cdwt)_firmware") {
  if (version_is_less(version: version, test_version: "1.64")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.64");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
