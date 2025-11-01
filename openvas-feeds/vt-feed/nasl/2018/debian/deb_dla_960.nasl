# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.890960");
  script_cve_id("CVE-2014-8354", "CVE-2014-8355", "CVE-2014-8562", "CVE-2014-8716", "CVE-2014-9841", "CVE-2015-8900", "CVE-2015-8901", "CVE-2015-8902", "CVE-2015-8903", "CVE-2017-7941", "CVE-2017-7943", "CVE-2017-8343", "CVE-2017-8344", "CVE-2017-8345", "CVE-2017-8346", "CVE-2017-8347", "CVE-2017-8348", "CVE-2017-8349", "CVE-2017-8350", "CVE-2017-8351", "CVE-2017-8352", "CVE-2017-8353", "CVE-2017-8354", "CVE-2017-8355", "CVE-2017-8356", "CVE-2017-8357", "CVE-2017-8765", "CVE-2017-8830", "CVE-2017-9098", "CVE-2017-9141", "CVE-2017-9142", "CVE-2017-9143", "CVE-2017-9144");
  script_tag(name:"creation_date", value:"2018-01-24 23:00:00 +0000 (Wed, 24 Jan 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Debian: Security Advisory (DLA-960)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-960");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-960");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imagemagick' package(s) announced via the DLA-960 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes several vulnerabilities in imagemagick: Various memory handling problems and cases of missing or incomplete input sanitising may result in denial of service, memory disclosure, or the execution of arbitrary code if malformed PCX, DCM, JPEG, PSD, HDR, MIFF, PDB, VICAR, SGI, SVG, AAI, MNG, EXR, MAT, SFW, JNG, PCD, XWD, PICT, BMP, MTV, SUN, EPT, ICON, DDS, or ART files are processed.

For Debian 7 Wheezy, these problems have been fixed in version 6.7.7.10-5+deb7u14.

We recommend that you upgrade your imagemagick packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);