# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70400");
  script_cve_id("CVE-2011-0862", "CVE-2011-0864", "CVE-2011-0865", "CVE-2011-0867", "CVE-2011-0868", "CVE-2011-0869", "CVE-2011-0871");
  script_tag(name:"creation_date", value:"2011-10-16 21:01:53 +0000 (Sun, 16 Oct 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2311)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2311");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2311");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openjdk-6' package(s) announced via the DSA-2311 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in OpenJDK, an implementation of the Java SE platform. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2011-0862

Integer overflow errors in the JPEG and font parser allow untrusted code (including applets) to elevate its privileges.

CVE-2011-0864

Hotspot, the just-in-time compiler in OpenJDK, mishandled certain byte code instructions, allowing untrusted code (including applets) to crash the virtual machine.

CVE-2011-0865

A race condition in signed object deserialization could allow untrusted code to modify signed content, apparently leaving its signature intact.

CVE-2011-0867

Untrusted code (including applets) could access information about network interfaces which was not intended to be public. (Note that the interface MAC address is still available to untrusted code.)

CVE-2011-0868

A float-to-long conversion could overflow, allowing untrusted code (including applets) to crash the virtual machine.

CVE-2011-0869

Untrusted code (including applets) could intercept HTTP requests by reconfiguring proxy settings through a SOAP connection.

CVE-2011-0871

Untrusted code (including applets) could elevate its privileges through the Swing MediaTracker code.

In addition, this update removes support for the Zero/Shark and Cacao Hotspot variants from the i386 and amd64 due to stability issues. These Hotspot variants are included in the openjdk-6-jre-zero and icedtea-6-jre-cacao packages, and these packages must be removed during this update.

For the oldstable distribution (lenny), these problems will be fixed in a separate DSA for technical reasons.

For the stable distribution (squeeze), these problems have been fixed in version 6b18-1.8.9-0.1~squeeze1.

For the testing distribution (wheezy) and the unstable distribution (sid), these problems have been fixed in version 6b18-1.8.9-0.1.

We recommend that you upgrade your openjdk-6 packages.");

  script_tag(name:"affected", value:"'openjdk-6' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);