#!/bin/sh
# Nautilus script "Encrypt with Shield": Nautilus passes the selected items as arguments.
exec shield-gui --encrypt-multi "$@"
