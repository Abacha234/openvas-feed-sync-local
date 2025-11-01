# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885875");
  script_version("2025-03-11T05:38:16+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-03-08 02:14:09 +0000 (Fri, 08 Mar 2024)");
  script_name("Fedora: Security Advisory for cpp-jwt (FEDORA-2024-56fbd2cbfa)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-56fbd2cbfa");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FHZDNU6F3BA75LWI5T3H3DUSSM5522IC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cpp-jwt'
  package(s) announced via the FEDORA-2024-56fbd2cbfa advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"JSON Web Token(JWT) is a JSON based standard (RFC-
7519) for creating assertions or access tokens that consists of some
claims (encoded within the assertion). This assertion can be used in some
kind of bearer authentication mechanism that the server will provide to
clients, and the clients can make use of the provided assertion for
accessing resources.");

  script_tag(name:"affected", value:"'cpp-jwt' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
