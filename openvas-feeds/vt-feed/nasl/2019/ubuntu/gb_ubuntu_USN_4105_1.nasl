# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844147");
  script_cve_id("CVE-2019-8675", "CVE-2019-8696");
  script_tag(name:"creation_date", value:"2019-08-21 02:00:52 +0000 (Wed, 21 Aug 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-30 02:22:00 +0000 (Fri, 30 Oct 2020)");

  script_name("Ubuntu: Security Advisory (USN-4105-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4105-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4105-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups' package(s) announced via the USN-4105-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stephan Zeisberg discovered that the CUPS SNMP backend incorrectly handled
encoded ASN.1 inputs. A remote attacker could possibly use this issue to
cause CUPS to crash by providing specially crafted network
traffic. (CVE-2019-8696, CVE-2019-8675)

It was discovered that CUPS did not properly handle client disconnection
events. A local attacker could possibly use this issue to cause a denial of
service or disclose memory from the CUPS server.");

  script_tag(name:"affected", value:"'cups' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
