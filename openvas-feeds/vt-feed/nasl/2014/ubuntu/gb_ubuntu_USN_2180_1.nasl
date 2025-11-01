# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841790");
  script_cve_id("CVE-2014-0049", "CVE-2014-0069");
  script_tag(name:"creation_date", value:"2014-05-02 04:40:48 +0000 (Fri, 02 May 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2180-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2180-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2180-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ti-omap4' package(s) announced via the USN-2180-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was discovered in the Kernel Virtual Machine (KVM) subsystem of the
Linux kernel. A guest OS user could exploit this flaw to execute arbitrary
code on the host OS. (CVE-2014-0049)

Al Viro discovered an error in how CIFS in the Linux kernel handles
uncached write operations. An unprivileged local user could exploit this
flaw to cause a denial of service (system crash), obtain sensitive
information from kernel memory, or possibly gain privileges.
(CVE-2014-0069)");

  script_tag(name:"affected", value:"'linux-ti-omap4' package(s) on Ubuntu 12.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
