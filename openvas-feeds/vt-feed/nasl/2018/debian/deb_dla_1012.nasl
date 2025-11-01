# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891012");
  script_cve_id("CVE-2017-2295");
  script_tag(name:"creation_date", value:"2018-02-04 23:00:00 +0000 (Sun, 04 Feb 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-24 13:36:00 +0000 (Thu, 24 May 2018)");

  script_name("Debian: Security Advisory (DLA-1012)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1012");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-1012");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'puppet' package(s) announced via the DLA-1012 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Versions of Puppet prior to 4.10.1 will deserialize data off the wire (from the agent to the server, in this case) with a attacker-specified format. This could be used to force YAML deserialization in an unsafe manner, which would lead to remote code execution.

For Debian 7 Wheezy, these problems have been fixed in version 2.7.23-1~deb7u4, by enabling PSON serialization on clients and refusing non-PSON formats on the server.

We recommend that you upgrade your puppet packages. Make sure you update all your clients before you update the server otherwise older clients won't be able to connect to the server.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'puppet' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);