use v5.36;

# Performs a comparison of 'path matching'  of a hash vs a sorted list


my @paths;
my $count=1;
my $depth=2;
for(1..$count){
  my $path="/";
  for(1..$depth){
    my $label=join "", map chr(ord("a")+rand(26)), 1..5;
    $path.="$label/";
  }
  push @paths, $path;
}
map say, @paths;


#Build a hash of hashes

my $top={};
my $current=$top;
for my $path (@paths){
  for(split "/", $path){
    $current{$_}={};
  }
  
}
