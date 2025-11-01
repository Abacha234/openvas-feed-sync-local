# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885343");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2023-47248");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-17 17:44:00 +0000 (Fri, 17 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-29 02:14:40 +0000 (Wed, 29 Nov 2023)");
  script_name("Fedora: Security Advisory for python-geopandas (FEDORA-2023-1c5e667fd0)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-1c5e667fd0");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FR34AIPXVTMB3XPRU5ULV5HHWPMRE33X");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-geopandas'
  package(s) announced via the FEDORA-2023-1c5e667fd0 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GeoPandas is a project to add support for geographic data to Pandas objects.

The goal of GeoPandas is to make working with geospatial data in Python easier.
It combines the capabilities of Pandas and Shapely, providing geospatial
operations in Pandas and a high-level interface to multiple geometries to
Shapely. GeoPandas enables you to easily do operations in Python that would
otherwise require a spatial database such as PostGIS.");

  script_tag(name:"affected", value:"'python-geopandas' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
