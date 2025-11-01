# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885162");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2023-22338", "CVE-2023-22840");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-18 18:46:00 +0000 (Fri, 18 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-11-05 02:19:36 +0000 (Sun, 05 Nov 2023)");
  script_name("Fedora: Security Advisory for oneVPL (FEDORA-2023-ea65146fd4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-ea65146fd4");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BFJISLKWZJB2WW2LKD66EGF6MM6KU3LB");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'oneVPL'
  package(s) announced via the FEDORA-2023-ea65146fd4 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The oneAPI Video Processing Library (oneVPL) provides a single video processing
API for encode, decode, and video processing that works across a wide range of
accelerators.

The base package is limited to the dispatcher and samples. To use oneVPL for
video processing you need to install at least one implementation. Current
implementations:

  - oneVPL-cpu for use on CPU

  - oneVPL-intel-gpu for use on Intel Xe graphics and newer

  - intel-mediasdk for use on legacy Intel graphics");

  script_tag(name:"affected", value:"'oneVPL' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
