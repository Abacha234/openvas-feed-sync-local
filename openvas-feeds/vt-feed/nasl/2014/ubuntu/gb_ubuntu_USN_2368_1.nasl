# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841992");
  script_cve_id("CVE-2013-2061");
  script_tag(name:"creation_date", value:"2014-10-03 03:57:58 +0000 (Fri, 03 Oct 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-2368-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2368-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2368-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openvpn' package(s) announced via the USN-2368-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenVPN incorrectly handled HMAC comparisons when
running in UDP mode. If a remote attacker were able to perform a
machine-in-the-middle attack, this flaw could possibly be used to perform a
plaintext recovery attack.");

  script_tag(name:"affected", value:"'openvpn' package(s) on Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
