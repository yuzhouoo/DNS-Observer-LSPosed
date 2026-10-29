package dev.yz.dnsobserver;

import android.app.Activity;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Insets;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.graphics.drawable.StateListDrawable;
import android.os.Build;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.text.style.StyleSpan;
import android.view.View;
import android.view.WindowInsets;
import android.view.WindowInsetsController;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Switch;
import android.widget.TextView;

/** Shared native UI styling. Does not read or change DNS / Root state. */
public final class TechUi {
    public static final int BG=0xff080f1b,PANEL=0xff101e30,TEXT=0xffeaf3ff,
        MUTED=0xffa4b7cc,CYAN=0xff53e0d0,GREEN=0xff80e4b1,RED=0xffff929f,AMBER=0xffffcb83;
    public static final int SECONDARY=0,PRIMARY=1,DANGER=2;
    private TechUi(){}
    public static int dp(Context c,int value){return Math.round(value*c.getResources().getDisplayMetrics().density);}
    public static GradientDrawable panel(Context c,int color,int radius){
        GradientDrawable d=new GradientDrawable();d.setColor(color);d.setCornerRadius(dp(c,radius));
        d.setStroke(dp(c,1),0xff29415c);return d;
    }
    public static Drawable backdrop(){return new GradientDrawable(GradientDrawable.Orientation.TL_BR,new int[]{0xff102136,BG,0xff0b1727});}
    private static Drawable shape(Context c,int fill,int stroke){
        GradientDrawable d=panel(c,fill,12);d.setStroke(dp(c,1),stroke);return d;
    }
    private static ColorStateList textColors(int normal,int selected){
        return new ColorStateList(new int[][]{new int[]{-android.R.attr.state_enabled},new int[]{android.R.attr.state_selected},new int[]{}},new int[]{0xff72859c,selected,normal});
    }
    public static void button(Button b,int tone){
        String key="dns-tech-button-"+tone;
        if(key.equals(b.getTag()))return;
        b.setTag(key);
        Context c=b.getContext();int accent=tone==DANGER?RED:tone==PRIMARY?CYAN:TEXT;
        b.setAllCaps(false);b.setTextSize(14);b.setTypeface(Typeface.create("sans-serif-medium",Typeface.NORMAL));
        b.setLetterSpacing(0.015f);b.setTextColor(textColors(accent,CYAN));
        b.setMinHeight(dp(c,52));b.setMinimumHeight(dp(c,52));b.setMinWidth(0);b.setMinimumWidth(0);
        b.setPadding(dp(c,14),dp(c,12),dp(c,14),dp(c,12));
        b.setBackgroundTintList(null);b.setStateListAnimator(null);
        StateListDrawable states=new StateListDrawable();
        states.addState(new int[]{-android.R.attr.state_enabled},shape(c,0xff111d2c,0xff26364a));
        states.addState(new int[]{android.R.attr.state_selected},shape(c,0xff143c48,CYAN));
        states.addState(new int[]{},shape(c,tone==DANGER?0xff341f31:tone==PRIMARY?0xff133847:0xff182b42,tone==DANGER?0xffa25164:tone==PRIMARY?0xff398a92:0xff35516e));
        b.setBackground(new RippleDrawable(ColorStateList.valueOf(0x3353e0d0),states,null));
    }
    public static void input(EditText e){
        Context c=e.getContext();e.setTextColor(TEXT);e.setHintTextColor(MUTED);e.setTextSize(15);
        e.setPadding(dp(c,14),dp(c,12),dp(c,14),dp(c,12));e.setMinHeight(dp(c,52));
        e.setBackgroundTintList(null);
        StateListDrawable d=new StateListDrawable();
        d.addState(new int[]{-android.R.attr.state_enabled},shape(c,0xff101a28,0xff24354a));
        d.addState(new int[]{android.R.attr.state_focused},shape(c,0xff112c3d,CYAN));
        d.addState(new int[]{},shape(c,PANEL,0xff35516e));e.setBackground(d);
    }
    public static void toggle(CompoundButton b){
        Context c=b.getContext();b.setTextSize(14);b.setTextColor(textColors(TEXT,TEXT));
        b.setMinHeight(dp(c,54));b.setPadding(dp(c,12),dp(c,10),dp(c,12),dp(c,10));
        ColorStateList tint=new ColorStateList(new int[][]{new int[]{-android.R.attr.state_enabled},new int[]{android.R.attr.state_checked},new int[]{}},new int[]{0xff52667c,CYAN,0xff8aa1b9});
        if(b instanceof Switch){Switch s=(Switch)b;s.setThumbTintList(tint);s.setTrackTintList(new ColorStateList(new int[][]{new int[]{-android.R.attr.state_enabled},new int[]{android.R.attr.state_checked},new int[]{}},new int[]{0xff26374a,0xff276474,0xff354b63}));s.setSwitchPadding(dp(c,12));}
        if(b instanceof CheckBox)((CheckBox)b).setButtonTintList(tint);
        StateListDrawable states=new StateListDrawable();
        states.addState(new int[]{android.R.attr.state_checked},shape(c,0xff12333e,0xff398a92));
        states.addState(new int[]{},shape(c,PANEL,0xff29415c));
        b.setBackground(new RippleDrawable(ColorStateList.valueOf(0x2453e0d0),states,null));
    }
    public static void disclosure(TextView t){
        Context c=t.getContext();t.setMinHeight(dp(c,48));
        t.setPadding(dp(c,10),dp(c,10),dp(c,10),dp(c,10));
        t.setBackground(new RippleDrawable(ColorStateList.valueOf(0x3353e0d0),shape(c,0xff112b3b,0xff294b61),null));
        t.setTextColor(CYAN);
    }
    public static void heading(TextView t){
        t.setTypeface(Typeface.create("sans-serif-medium",Typeface.NORMAL));t.setLetterSpacing(0.025f);
        t.setTextColor(CYAN);t.setPadding(0,dp(t.getContext(),22),0,dp(t.getContext(),10));
    }
    public static void badge(TextView t,boolean success){
        t.setPadding(dp(t.getContext(),10),dp(t.getContext(),5),dp(t.getContext(),10),dp(t.getContext(),5));
        t.setBackground(shape(t.getContext(),success?0xff143932:0xff392435,success?0xff347760:0xff8a4b61));
        t.setTextColor(success?GREEN:RED);
    }
    public static void overview(TextView view,String[] labels,String[] values,int[] colors){
        SpannableStringBuilder text=new SpannableStringBuilder();
        for(int i=0;i<labels.length;i++){
            if(i>0)text.append("\n");int from=text.length();text.append(labels[i]).append("  ");
            text.setSpan(new ForegroundColorSpan(MUTED),from,text.length(),Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            from=text.length();text.append(values[i]);
            text.setSpan(new ForegroundColorSpan(colors[i]),from,text.length(),Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            text.setSpan(new StyleSpan(Typeface.BOLD),from,text.length(),Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }
        view.setText(text);view.setLineSpacing(dp(view.getContext(),7),1f);
    }
    public static void spaced(View v){
        if(v.getLayoutParams() instanceof LinearLayout.LayoutParams){LinearLayout.LayoutParams p=(LinearLayout.LayoutParams)v.getLayoutParams();p.bottomMargin=dp(v.getContext(),8);v.setLayoutParams(p);}
    }
    /** Apply to the outermost content view ONCE. Always add to the original padding,
     * never accumulate prior insets; includes cutout/landscape, gesture nav and IME. */
    public static void safeScreen(Activity activity,View root){
        activity.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
        activity.getWindow().setStatusBarColor(Color.TRANSPARENT);
        activity.getWindow().setNavigationBarColor(BG);
        activity.getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE|WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);
        if(Build.VERSION.SDK_INT>=30){
            activity.getWindow().setDecorFitsSystemWindows(false);
            WindowInsetsController controller=activity.getWindow().getInsetsController();
            if(controller!=null)controller.setSystemBarsAppearance(0,WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS|WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS);
        }else activity.getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LAYOUT_STABLE|View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN|View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION);
        final int left=root.getPaddingLeft(),top=root.getPaddingTop(),right=root.getPaddingRight(),bottom=root.getPaddingBottom();
        root.setOnApplyWindowInsetsListener((v,insets)->{
            int l,t,r,b;
            if(Build.VERSION.SDK_INT>=30){Insets bars=insets.getInsets(WindowInsets.Type.systemBars()|WindowInsets.Type.displayCutout());
                l=bars.left;t=bars.top;r=bars.right;b=Math.max(bars.bottom,insets.getInsets(WindowInsets.Type.ime()).bottom);
            }else{l=insets.getSystemWindowInsetLeft();t=insets.getSystemWindowInsetTop();r=insets.getSystemWindowInsetRight();b=insets.getSystemWindowInsetBottom();
                if(insets.getDisplayCutout()!=null){l=Math.max(l,insets.getDisplayCutout().getSafeInsetLeft());t=Math.max(t,insets.getDisplayCutout().getSafeInsetTop());r=Math.max(r,insets.getDisplayCutout().getSafeInsetRight());b=Math.max(b,insets.getDisplayCutout().getSafeInsetBottom());}}
            v.setPadding(left+l,top+t,right+r,bottom+b);
            return Build.VERSION.SDK_INT>=30?WindowInsets.CONSUMED:insets.consumeSystemWindowInsets().consumeDisplayCutout();
        });
        root.post(root::requestApplyInsets);
    }
}
