TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lnetfilter_queue

SOURCES += \
        harmfulsiteblocker.cpp \
        main.cpp \
        netfiltermanager.cpp

HEADERS += \
    harmfulsiteblocker.h \
    netfiltermanager.h
