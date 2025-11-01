# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840907");
  script_cve_id("CVE-2012-1053", "CVE-2012-1054");
  script_tag(name:"creation_date", value:"2012-03-09 13:26:11 +0000 (Fri, 09 Mar 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1372-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1372-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1372-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'puppet' package(s) announced via the USN-1372-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Puppet did not drop privileges when executing
commands as different users. If an attacker had control of the execution
manifests or the executed command, this could be used to execute code with
elevated group permissions (typically root). (CVE-2012-1053)

It was discovered that Puppet unsafely opened files when the k5login type
is used to manage files. A local attacker could exploit this to overwrite
arbitrary files and escalate privileges. (CVE-2012-1054)");

  script_tag(name:"affected", value:"'puppet' package(s) on Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04, Ubuntu 11.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
