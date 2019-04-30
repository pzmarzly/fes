#!/bin/bash
if [ -z "$PATH_TO_ROBOTO" ]; then
    PATH_TO_ROBOTO=/usr/share/fonts/TTF/Roboto-Regular.ttf
fi

diag() {
    seqdiag --no-transparency -f $PATH_TO_ROBOTO -a $1
}
diag connection.diag
