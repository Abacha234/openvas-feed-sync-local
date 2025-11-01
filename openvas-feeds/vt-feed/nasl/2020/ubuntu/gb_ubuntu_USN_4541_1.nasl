# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844616");
  script_cve_id("CVE-2018-19490", "CVE-2018-19491", "CVE-2018-19492");
  script_tag(name:"creation_date", value:"2020-09-26 03:00:39 +0000 (Sat, 26 Sep 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-28 20:15:00 +0000 (Mon, 28 Sep 2020)");

  script_name("Ubuntu: Security Advisory (USN-4541-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4541-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4541-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnuplot' package(s) announced via the USN-4541-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tim Blazytko, Cornelius Aschermann, Sergej Schumilo and Nils Bars
discovered that Gnuplot did not properly validate string sizes in the
df_generate_ascii_array_entry function. An attacker could possibly use
this issue to cause a heap buffer overflow, resulting in a denial of
service attack or arbitrary code execution. (CVE-2018-19490)

Tim Blazytko, Cornelius Aschermann, Sergej Schumilo and Nils Bars
discovered that Gnuplot did not properly validate string sizes in the
PS_options function when the Gnuplot postscript terminal is used as a
backend. An attacker could possibly use this issue to cause a buffer
overflow, resulting in a denial of service attack or arbitrary code
execution. (CVE-2018-19491)

Tim Blazytko, Cornelius Aschermann, Sergej Schumilo and Nils Bars
discovered that Gnuplot did not properly validate string sizes in the
cairotrm_options function when the Gnuplot postscript terminal is used as
a backend. An attacker could possibly use this issue to cause a buffer
overflow, resulting in a denial of service attack or arbitrary code
execution. (CVE-2018-19492)");

  script_tag(name:"affected", value:"'gnuplot' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
