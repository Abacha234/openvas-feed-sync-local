# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886445");
  script_version("2025-03-11T05:38:16+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-05-27 10:41:01 +0000 (Mon, 27 May 2024)");
  script_name("Fedora: Security Advisory for abseil-cpp (FEDORA-2024-bb70b21754)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-bb70b21754");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LXVP4BZNL6R7OR236CNZ2BEE2CYSFNED");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'abseil-cpp'
  package(s) announced via the FEDORA-2024-bb70b21754 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Abseil is an open-source collection of C++ library code designed to augment
the C++ standard library. The Abseil library code is collected from
Google&#39,s own C++ code base, has been extensively tested and used in
production, and is the same code we depend on in our daily coding lives.

In some cases, Abseil provides pieces missing from the C++ standard, in
others, Abseil provides alternatives to the standard for special needs we&#39,ve
found through usage in the Google code base. We denote those cases clearly
within the library code we provide you.

Abseil is not meant to be a competitor to the standard library, we&#39,ve just
found that many of these utilities serve a purpose within our code base,
and we now want to provide those resources to the C++ community as a whole.");

  script_tag(name:"affected", value:"'abseil-cpp' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
