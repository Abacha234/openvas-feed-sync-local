# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892806");
  script_cve_id("CVE-2018-10841", "CVE-2018-1088", "CVE-2018-10904", "CVE-2018-10907", "CVE-2018-10911", "CVE-2018-10913", "CVE-2018-10914", "CVE-2018-10923", "CVE-2018-10926", "CVE-2018-10927", "CVE-2018-10928", "CVE-2018-10929", "CVE-2018-10930", "CVE-2018-14652", "CVE-2018-14653", "CVE-2018-14654", "CVE-2018-14659", "CVE-2018-14660", "CVE-2018-14661");
  script_tag(name:"creation_date", value:"2021-11-02 02:00:20 +0000 (Tue, 02 Nov 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-30 22:13:00 +0000 (Tue, 30 Nov 2021)");

  script_name("Debian: Security Advisory (DLA-2806)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2806");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2806");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/glusterfs");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'glusterfs' package(s) announced via the DLA-2806 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities were discovered in GlusterFS, a clustered file system. Buffer overflows and path traversal issues may lead to information disclosure, denial-of-service or the execution of arbitrary code.

For Debian 9 stretch, these problems have been fixed in version 3.8.8-1+deb9u1.

We recommend that you upgrade your glusterfs packages.

For the detailed security status of glusterfs please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'glusterfs' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);