# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887377");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2024-6345");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-08-13 04:04:37 +0000 (Tue, 13 Aug 2024)");
  script_name("Fedora: Security Advisory for pypy (FEDORA-2024-c5152808e4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-c5152808e4");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/Y4WF4TVRV3N44EVKVPX7DCMO52UIGNCG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pypy'
  package(s) announced via the FEDORA-2024-c5152808e4 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"PyPy's implementation of Python, featuring a Just-In-Time compiler on some CPU
architectures, and various optimized implementations of the standard types
(strings, dictionaries, etc)</p>
<p>This build of PyPy has JIT-compilation enabled");

  script_tag(name:"affected", value:"'pypy' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
