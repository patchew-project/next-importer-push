QEMU Python Tooling
===================

This directory houses Python tooling used by the QEMU project to build,
configure, and test QEMU. It is organized by namespace (``qemu``), and
then by package (``qemu/machine``, ``qemu/qmp``).

``setup.py`` is used by ``pip`` to install this tooling to the current
environment. ``setup.cfg`` provides the packaging configuration used by
setup.py in a setuptools specific format. You will generally invoke it
by doing one of the following:

1. ``pip3 install .`` will install these packages to your current
   environment. If you are inside a virtual environment, they will
   install there. If you are not, it will attempt to install to the
   global environment, which is not recommended.

2. ``pip3 install --user .`` will install these packages to your user's
   local python packages. If you are inside of a virtual environment,
   this will fail.

If you amend the ``-e`` argument, pip will install in "editable" mode;
which installs a version of the package that installs a forwarder
pointing to these files, such that the package always reflects the
latest version in your git tree.

See `Installing packages using pip and virtual environments
<https://packaging.python.org/guides/installing-using-pip-and-virtual-environments/>`_
for more information.


Files in this directory
-----------------------

- ``qemu/`` Python package source directory.
- ``PACKAGE.rst`` is used as the README file that is visible on PyPI.org.
- ``README.rst`` you are here!
- ``VERSION`` contains the PEP-440 compliant version used to describe
  this package; it is referenced by ``setup.cfg``.
- ``setup.cfg`` houses setuptools package configuration.
- ``setup.py`` is the setuptools installer used by pip; See above.
