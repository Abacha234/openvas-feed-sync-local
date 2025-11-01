# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841935");
  script_cve_id("CVE-2014-5206", "CVE-2014-5207");
  script_tag(name:"creation_date", value:"2014-08-19 03:59:19 +0000 (Tue, 19 Aug 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2317-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2317-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2317-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-trusty' package(s) announced via the USN-2317-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Eric W. Biederman discovered a flaw with the mediation of mount flags in
the Linux kernel's user namespace subsystem. An unprivileged user could
exploit this flaw to by-pass mount restrictions, and potentially gain
administrative privileges. (CVE-2014-5207)

Kenton Varda discovered a flaw with read-only bind mounds when used with
user namespaces. An unprivileged local user could exploit this flaw to gain
full write privileges to a mount that should be read only. (CVE-2014-5206)");

  script_tag(name:"affected", value:"'linux-lts-trusty' package(s) on Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
