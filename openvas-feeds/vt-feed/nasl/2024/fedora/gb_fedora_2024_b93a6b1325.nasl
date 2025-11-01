# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886746");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2023-50471");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-19 20:51:50 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-05-27 10:46:13 +0000 (Mon, 27 May 2024)");
  script_name("Fedora: Security Advisory for cjson (FEDORA-2024-b93a6b1325)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-b93a6b1325");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YQOQ7CAOYBNHGAMNOR7ELGLC22HV3ZQV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cjson'
  package(s) announced via the FEDORA-2024-b93a6b1325 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"cJSON aims to be the dumbest possible parser that you can get your job
done with. It&#39,s a single file of C, and a single header file.");

  script_tag(name:"affected", value:"'cjson' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
