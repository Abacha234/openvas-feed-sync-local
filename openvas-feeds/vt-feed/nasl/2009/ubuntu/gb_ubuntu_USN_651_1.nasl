# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840344");
  script_cve_id("CVE-2008-1447", "CVE-2008-2376", "CVE-2008-3443", "CVE-2008-3655", "CVE-2008-3656", "CVE-2008-3657", "CVE-2008-3790", "CVE-2008-3905");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-651-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-651-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-651-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby1.8' package(s) announced via the USN-651-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Akira Tagoh discovered a vulnerability in Ruby which lead to an integer
overflow. If a user or automated system were tricked into running a
malicious script, an attacker could cause a denial of service or
possibly execute arbitrary code with the privileges of the user
invoking the program. (CVE-2008-2376)

Laurent Gaffie discovered that Ruby did not properly check for memory
allocation failures. If a user or automated system were tricked into
running a malicious script, an attacker could cause a denial of
service. (CVE-2008-3443)

Keita Yamaguchi discovered several safe level vulnerabilities in Ruby.
An attacker could use this to bypass intended access restrictions.
(CVE-2008-3655)

Keita Yamaguchi discovered that WEBrick in Ruby did not properly
validate paths ending with '.'. A remote attacker could send a crafted
HTTP request and cause a denial of service. (CVE-2008-3656)

Keita Yamaguchi discovered that the dl module in Ruby did not check
the taintness of inputs. An attacker could exploit this vulnerability
to bypass safe levels and execute dangerous functions. (CVE-2008-3657)

Luka Treiber and Mitja Kolsek discovered that REXML in Ruby did not
always use expansion limits when processing XML documents. If a user or
automated system were tricked into open a crafted XML file, an attacker
could cause a denial of service via CPU consumption. (CVE-2008-3790)

Jan Lieskovsky discovered several flaws in the name resolver of Ruby. A
remote attacker could exploit this to spoof DNS entries, which could
lead to misdirected traffic. This is a different vulnerability from
CVE-2008-1447. (CVE-2008-3905)");

  script_tag(name:"affected", value:"'ruby1.8' package(s) on Ubuntu 6.06, Ubuntu 7.04, Ubuntu 7.10, Ubuntu 8.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
