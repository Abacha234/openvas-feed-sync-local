# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842662");
  script_tag(name:"creation_date", value:"2016-03-01 05:39:04 +0000 (Tue, 01 Mar 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-2913-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2913-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2913-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1528645");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glib-networking' package(s) announced via the USN-2913-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2913-1 removed 1024-bit RSA CA certificates from the ca-certificates
package. This update adds support for alternate certificate chains to the
glib-networking package to properly handle the removal.

Original advisory details:

 The ca-certificates package contained outdated CA certificates. This update
 refreshes the included certificates to those contained in the 20160104
 package, including the removal of the SPI CA and CA certificates with
 1024-bit RSA keys.");

  script_tag(name:"affected", value:"'glib-networking' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
