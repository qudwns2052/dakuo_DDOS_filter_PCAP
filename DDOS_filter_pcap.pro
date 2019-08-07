TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += \
        ifctl.cpp \
        main.cpp \
        packet_filter.cpp

HEADERS += \
    ifctl.h \
    packet_filter.h \
    packet_structure.h
