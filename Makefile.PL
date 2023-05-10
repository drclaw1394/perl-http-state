use 5.036000;
use ExtUtils::MakeMaker;
WriteMakefile(
    NAME              => 'HTTP::State',
    VERSION_FROM      => 'lib/HTTP/State.pm', 
    PREREQ_PM         => {
      "Log::ger"=>0,
      "Log::OK"=>0,
      "Object::Pad"=>0,
      "List::Insertion"=>0,
      "Mozilla::PublicSuffix"=>0,
      "Time::Local"=>0

    },

    ABSTRACT_FROM     => 'lib/HTTP/State.pod', 
    AUTHOR            => 'Ruben Westerberg <drclaw@mac.com>',
    LICENSE           => 'mit',
);
