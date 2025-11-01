# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884925");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2023-41915");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-13 14:32:00 +0000 (Wed, 13 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-10-04 01:16:46 +0000 (Wed, 04 Oct 2023)");
  script_name("Fedora: Security Advisory for prrte (FEDORA-2023-1185eca900)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-1185eca900");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/A4R7F735CY4VBE4N7TXUYFTDZLS3MRHS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'prrte'
  package(s) announced via the FEDORA-2023-1185eca900 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"PRRTE is the PMIx Reference Run Time Environment.

The project is formally referred to in documentation by 'PRRTE', and
the GitHub repository is 'openpmix/prrte'.

However, we have found that most users do not like typing the two
consecutive 'r's in the name. Hence, all of the internal API symbols,
environment variables, MCA frameworks, and CLI executables all use the
abbreviated 'prte' (one 'r', not two) for convenience.");

  script_tag(name:"affected", value:"'prrte' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
