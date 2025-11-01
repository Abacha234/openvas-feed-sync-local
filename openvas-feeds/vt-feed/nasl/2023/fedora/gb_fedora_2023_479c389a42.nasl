# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884805");
  script_version("2025-03-11T05:38:16+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2023-09-16 01:15:29 +0000 (Sat, 16 Sep 2023)");
  script_name("Fedora: Security Advisory for python3.10 (FEDORA-2023-479c389a42)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-479c389a42");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PG5NRLHEHAP5UFRB3OS7JSI3TD2OTNVX");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.10'
  package(s) announced via the FEDORA-2023-479c389a42 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Python 3.10 is an accessible, high-level, dynamically typed, interpreted
programming language, designed with an emphasis on code readability.
It includes an extensive standard library, and has a vast ecosystem of
third-party libraries.

The python3.10 package provides the 'python3.10' executable: the reference
interpreter for the Python language, version 3.
The majority of its standard library is provided in the python3.10-libs package,
which should be installed automatically along with python3.10.
The remaining parts of the Python standard library are broken out into the
python3.10-tkinter and python3.10-test packages, which may need to be installed
separately.

Documentation for Python is provided in the python3.10-docs package.

Packages containing additional libraries for Python are generally named with
the 'python3.10-' prefix.");

  script_tag(name:"affected", value:"'python3.10' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
