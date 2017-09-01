//
//  ViewController.m
//  MachOSignDemo
//
//  Created by 罗贤明 on 2017/9/1.
//  Copyright © 2017年 罗贤明. All rights reserved.
//

#import "ViewController.h"
#import "MachOSignature.h"

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UITextView *Sign;
@property (weak, nonatomic) IBOutlet UITextView *Sha1;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    NSDictionary *dic = [MachOSignature loadSignature];
    if (dic) {
        _Sign.text = dic[@"Entitlements"];
        _Sha1.text = dic[@"EntitlementsHash"];
    }else {
        _Sign.text = @"获取签名证书失败，当前可能是模拟器。 如果不是模拟器，且加载失败，请与我沟通！";
    }
    
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
