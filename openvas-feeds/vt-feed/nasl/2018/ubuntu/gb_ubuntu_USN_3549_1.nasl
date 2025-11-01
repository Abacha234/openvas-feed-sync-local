# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843436");
  script_cve_id("CVE-2017-5715", "CVE-2017-5753");
  script_tag(name:"creation_date", value:"2018-01-30 06:53:35 +0000 (Tue, 30 Jan 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-24 17:43:00 +0000 (Thu, 24 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-3549-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3549-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3549-1");
  script_xref(name:"URL", value:"https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/SpectreAndMeltdown");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-kvm, linux-meta-kvm' package(s) announced via the USN-3549-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jann Horn discovered that microprocessors utilizing speculative
execution and branch prediction may allow unauthorized memory
reads via sidechannel attacks. This flaw is known as Spectre. A
local attacker could use this to expose sensitive information,
including kernel memory. (CVE-2017-5715, CVE-2017-5753)");

  script_tag(name:"affected", value:"'linux-kvm, linux-meta-kvm' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
