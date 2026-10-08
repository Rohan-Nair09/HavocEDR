[app]
title = HavocEDR
project_dir = .
input_file = main.py
exec_directory = release

[python]
packages = Nuitka==4.2.2

[qt]
modules = Core,Gui,Widgets
plugins = accessiblebridge,iconengines,imageformats,platforminputcontexts,platforms,platformthemes,styles

[nuitka]
mode = onefile
extra_args = --quiet --noinclude-qt-translations --assume-yes-for-downloads --windows-console-mode=disable --include-package=dashboard --include-package=monitoring --include-package=database --include-package=detection_engine --include-package=ai --include-package=config --include-package=utils

