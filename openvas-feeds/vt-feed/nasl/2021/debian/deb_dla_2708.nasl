# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892708");
  script_cve_id("CVE-2019-18218", "CVE-2020-7071", "CVE-2021-21702", "CVE-2021-21704", "CVE-2021-21705");
  script_tag(name:"creation_date", value:"2021-07-16 03:00:19 +0000 (Fri, 16 Jul 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-09 17:55:00 +0000 (Wed, 09 Nov 2022)");

  script_name("Debian: Security Advisory (DLA-2708)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2708");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2708");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/php7.0");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php7.0' package(s) announced via the DLA-2708 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in php5, a server-side, HTML-embedded scripting language. An attacker could cause denial of service (DoS), memory corruption and potentially execution of arbitrary code, and server-side request forgery (SSRF) bypass.

CVE-2019-18218

fileinfo: cdf_read_property_info in cdf.c does not restrict the number of CDF_VECTOR elements, which allows a heap-based buffer overflow (4-byte out-of-bounds write).

CVE-2020-7071

When validating URL with functions like filter_var($url, FILTER_VALIDATE_URL), PHP will accept an URL with invalid password as valid URL. This may lead to functions that rely on URL being valid to mis-parse the URL and produce wrong data as components of the URL.

CVE-2021-21702

When using SOAP extension to connect to a SOAP server, a malicious SOAP server could return malformed XML data as a response that would cause PHP to access a null pointer and thus cause a crash.

CVE-2021-21704

Multiple firebird issues.

CVE-2021-21705

SSRF bypass in FILTER_VALIDATE_URL.

For Debian 9 stretch, these problems have been fixed in version 7.0.33-0+deb9u11.

We recommend that you upgrade your php7.0 packages.

For the detailed security status of php7.0 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'php7.0' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);