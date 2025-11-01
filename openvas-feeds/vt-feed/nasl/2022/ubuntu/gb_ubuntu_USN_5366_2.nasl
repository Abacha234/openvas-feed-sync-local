# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845339");
  script_cve_id("CVE-2022-25308", "CVE-2022-25309", "CVE-2022-25310");
  script_tag(name:"creation_date", value:"2022-04-28 01:01:44 +0000 (Thu, 28 Apr 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-5366-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5366-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5366-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fribidi' package(s) announced via the USN-5366-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5366-1 fixed several vulnerabilities in FriBidi. This update provides the
corresponding updates for Ubuntu 22.04 LTS.

Original advisory details:

 It was discovered that FriBidi incorrectly handled processing of input strings
 resulting in memory corruption. An attacker could use this issue to cause
 FriBidi to crash, resulting in a denial of service, or potentially execute
 arbitrary code. (CVE-2022-25308)

 It was discovered that FriBidi incorrectly validated input data to its CapRTL
 unicode encoder, resulting in memory corruption. An attacker could use this
 issue to cause FriBidi to crash, resulting in a denial of service, or
 potentially execute arbitrary code. (CVE-2022-25309)

 It was discovered that FriBidi incorrectly handled empty input when removing
 marks from unicode strings, resulting in a crash. An attacker could use this
 to cause FriBidi to crash, resulting in a denial of service, or potentially
 execute arbitrary code. (CVE-2022-25310)");

  script_tag(name:"affected", value:"'fribidi' package(s) on Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
