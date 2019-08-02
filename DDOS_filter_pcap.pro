TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += \
        linked_list.cpp \
        main.cpp \
        packet_filter.cpp

HEADERS += \
    linked_list.h \
    packet_filter.h \
    packet_structure.h
