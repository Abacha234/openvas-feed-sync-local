# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856186");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2021-33813");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-21 22:21:48 +0000 (Mon, 21 Jun 2021)");
  script_tag(name:"creation_date", value:"2024-06-05 01:00:55 +0000 (Wed, 05 Jun 2024)");
  script_name("openSUSE: Security Advisory for Java (SUSE-SU-2024:1874-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1874-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/AEZLYLMXDOQSSAVOJL4DPPUA25532JGY");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Java'
  package(s) announced via the SUSE-SU-2024:1874-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for Java fixes thefollowing issues:

  apiguardian was updated to version 1.1.2:

  * Added LICENSE/NOTICE to the generated jar

  * Allow @API to be declared at the package level

  * Explain usage of Status.DEPRECATED

  * Include OSGi metadata in manifest

  assertj-core was implemented at version 3.25.3:

  * New package implementation needed by Junit5

  byte-buddy was updated to version v1.14.16:

  * `byte-buddy` is required by `assertj-core`

  * Changes in version v1.14.16:

  * Update ASM and introduce support for Java 23.

  * Changes in version v1.14.15:

  * Allow attaching from root on J9.

  * Changes of v1.14.14:

  * Adjust type validation to accept additional names that are legal in the
      class file format.

  * Fix dynamic attach on Windows when a service user is active.

  * Avoid failure when using Android's strict mode.

  dom4j was updated to version 2.1.4:

  * Improvements and potentially breaking changes:

  * Added new factory method org.dom4j.io.SAXReader.createDefault(). It has more
      secure defaults than new SAXReader(), which uses system
      XMLReaderFactory.createXMLReader() or
      SAXParserFactory.newInstance().newSAXParser().

  * If you use some optional dependency of dom4j (for example Jaxen, xsdlib
      etc.), you need to specify an explicit dependency on it in your project.
      They are no longer marked as a mandatory transitive dependency by dom4j.

  * Following SAX parser features are disabled by default in
      DocumentHelper.parse() for security reasons (they were enabled in previous
      versions):

  * Other changes:

  * Do not depend on jtidy, since it is not used during build

  * Fixed license to Plexus

  * JPMS: Add the Automatic-Module-Name attribute to the manifest.

  * Make a separate flavour for a minimal `dom4j-bootstrap` package used to
      build `jaxen` and full `dom4j`

  * Updated pull-parser version

  * Reuse the writeAttribute method in writeAttributes

  * Support build on OS with non-UTF8 as default charset

  * Gradle: add an automatic module name

  * Use Correct License Name 'Plexus'

  * Possible vulnerability of DocumentHelper.parseText() to XML injection

  * CVS directories left in the source tree

  * XMLWriter does not escape supplementary unicode characters correctly

  * writer.writeOpen(x) doesn't write namespaces

  * Fixed concurrency problem with QNameCache

  * All dependencies are option ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'Java' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
